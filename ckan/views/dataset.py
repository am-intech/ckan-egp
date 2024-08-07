# encoding: utf-8
from __future__ import annotations

import logging
import inspect
from collections import OrderedDict
from functools import partial

import sqlalchemy
from sqlalchemy.orm import aliased
from typing_extensions import TypeAlias
from urllib.parse import urlencode
from typing import Any, Iterable, Optional, Union, cast

from flask import Blueprint
from flask.views import MethodView
from jinja2.exceptions import TemplateNotFound
from werkzeug.datastructures import MultiDict
from ckan.common import asbool, current_user

import ckan.lib.base as base
from ckan.lib.helpers import helper_functions as h
from ckan.lib.helpers import Page
import ckan.lib.navl.dictization_functions as dict_fns
import ckan.logic as logic
import ckan.model as model
import ckan.plugins as plugins
import ckan.authz as authz
from ckan.common import _, config, g, request
from ckan.views.home import CACHE_PARAMETERS
from ckan.lib.plugins import lookup_package_plugin
from ckan.lib.search import SearchError, SearchQueryError, SearchIndexError
from ckan.types import Context, Response, DataDict

NotFound = logic.NotFound
NotAuthorized = logic.NotAuthorized
ValidationError = logic.ValidationError
check_access = logic.check_access
get_action = logic.get_action
tuplize_dict = logic.tuplize_dict
clean_dict = logic.clean_dict
parse_params = logic.parse_params
flatten_to_string_key = logic.flatten_to_string_key
_or_ = sqlalchemy.or_
_and_ = sqlalchemy.and_
_select = sqlalchemy.select

log = logging.getLogger(__name__)

dataset = Blueprint(
    'dataset',
    __name__,
    url_prefix='/dataset',
    url_defaults={'package_type': 'dataset'}
)
@dataset.before_request
def before_request() -> None:
    if not current_user or current_user.is_anonymous:
        h.flash_error(_('Not authorized to see this page'))
        return h.redirect_to('user.login')  # type: ignore


def _setup_template_variables(context: Context,
                              data_dict: dict[str, Any],
                              package_type: Optional[str] = None) -> None:
    return lookup_package_plugin(package_type).setup_template_variables(
        context, data_dict
    )


def _get_pkg_template(template_type: str,
                      package_type: Optional[str] = None) -> str:
    pkg_plugin = lookup_package_plugin(package_type)
    method = getattr(pkg_plugin, template_type)
    signature = inspect.signature(method)
    if len(signature.parameters):
        return method(package_type)
    else:
        return method()


def _encode_params(params: Iterable[tuple[str, Any]]):
    return [(k, v.encode(u'utf-8') if isinstance(v, str) else str(v))
            for k, v in params]


Params: TypeAlias = "list[tuple[str, Any]]"


def url_with_params(url: str, params: Params) -> str:
    params = _encode_params(params)
    return url + u'?' + urlencode(params)


def search_url(params: Params, package_type: Optional[str] = None) -> str:
    if not package_type:
        package_type = u'dataset'
    url = h.url_for(u'{0}.search'.format(package_type))
    return url_with_params(url, params)


def remove_field(package_type: Optional[str],
                 key: str,
                 value: Optional[str] = None,
                 replace: Optional[str] = None):
    if not package_type:
        package_type = u'dataset'
    url = h.url_for(u'{0}.search'.format(package_type))
    return h.remove_url_param(
        key,
        value=value,
        replace=replace,
        alternative_url=url
    )


def _sort_by(params_nosort: Params, package_type: str,
             fields: Iterable[tuple[str, str]]) -> str:
    """Sort by the given list of fields.

    Each entry in the list is a 2-tuple: (fieldname, sort_order)
    eg - [(u'metadata_modified', u'desc'), (u'name', u'asc')]
    If fields is empty, then the default ordering is used.
    """
    params = params_nosort[:]

    if fields:
        sort_string = u', '.join(u'%s %s' % f for f in fields)
        params.append((u'sort', sort_string))
    return search_url(params, package_type)


def _pager_url(params_nopage: Params,
               package_type: str,
               q: Any = None,  # noqa
               page: Optional[int] = None) -> str:
    params = list(params_nopage)
    params.append((u'page', page))
    return search_url(params, package_type)


def _tag_string_to_list(tag_string: str) -> list[dict[str, str]]:
    """This is used to change tags from a sting to a list of dicts.
    """
    out: list[dict[str, str]] = []
    for tag in tag_string.split(u','):
        tag = tag.strip()
        if tag:
            out.append({u'name': tag, u'state': u'active'})
    return out


def _form_save_redirect(pkg_name: str,
                        action: str,
                        package_type: Optional[str] = None) -> Response:
    """This redirects the user to the CKAN package/read page,
    unless there is request parameter giving an alternate location,
    perhaps an external website.
    @param pkg_name - Name of the package just edited
    @param action - What the action of the edit was
    """
    assert action in (u'new', u'edit')
    url = request.args.get(u'return_to') or config.get(
        u'package_%s_return_url' % action
    )
    if url:
        url = url.replace(u'<NAME>', pkg_name)
    else:
        if not package_type:
            package_type = u'dataset'
        url = h.url_for(u'{0}.read'.format(package_type), id=pkg_name)
    return h.redirect_to(url)


def _get_package_type(id: str) -> str:
    """
    Given the id of a package this method will return the type of the
    package, or 'dataset' if no type is currently set
    """
    pkg = model.Package.get(id)
    if pkg:
        return pkg.type or u'dataset'
    return u'dataset'


def _get_search_details() -> dict[str, Any]:
    fq = u''

    # fields_grouped will contain a dict of params containing
    # a list of values eg {u'tags':[u'tag1', u'tag2']}

    fields = []
    fields_grouped = {}
    search_extras: 'MultiDict[str, Any]' = MultiDict()

    for (param, value) in request.args.items(multi=True):
        if param not in [u'q', u'page', u'sort'] \
                and len(value) and not param.startswith(u'_'):
            if not param.startswith(u'ext_'):
                fields.append((param, value))
                fq += u' %s:"%s"' % (param, value)
                if param not in fields_grouped:
                    fields_grouped[param] = [value]
                else:
                    fields_grouped[param].append(value)
            else:
                search_extras.update({param: value})

    extras = dict([
        (k, v[0]) if len(v) == 1 else (k, v)
        for k, v in search_extras.lists()
    ])
    return {
        'fields': fields,
        'fields_grouped': fields_grouped,
        'fq': fq,
        'search_extras': extras,
    }


def search(package_type: str) -> str:
    extra_vars: dict[str, Any] = {}

    try:
        context = cast(Context, {
            'model': model,
            'user': current_user.name,
            'auth_user_obj': current_user
        })
        check_access('site_read', context)
    except NotAuthorized:
        base.abort(403, _('Not authorized to see this page'))

    # unicode format (decoded from utf8)
    extra_vars[u'q'] = q = request.args.get(u'q', u'')

    extra_vars['query_error'] = False
    page = h.get_page_number(request.args)

    limit = config.get('ckan.datasets_per_page')

    # most search operations should reset the page counter:
    params_nopage = [(k, v) for k, v in request.args.items(multi=True) if k != 'page']

    extra_vars['remove_field'] = partial(remove_field, package_type)

    sort_by = request.args.get('sort', None)
    params_nosort = [(k, v) for k, v in params_nopage if k != 'sort']

    extra_vars['sort_by'] = partial(_sort_by, params_nosort, package_type)

    if not sort_by:
        sort_by_fields = []
    else:
        sort_by_fields = [field.split()[0] for field in sort_by.split(',')]
    extra_vars['sort_by_fields'] = sort_by_fields

    pager_url = partial(_pager_url, params_nopage, package_type)

    details = _get_search_details()
    extra_vars['fields'] = details['fields']
    extra_vars['fields_grouped'] = details['fields_grouped']
    fq = details['fq']
    search_extras = details[u'search_extras']

    context = cast(Context, {
        'model': model,
        'session': model.Session,
        'user': current_user.name,
        'for_view': True,
        'auth_user_obj': current_user
    })

    facets: dict[str, str] = OrderedDict()

    org_label = h.humanize_entity_type('organization', h.default_group_type('organization'), 'facet label') or _('Organizations')
    group_label = h.humanize_entity_type('group', h.default_group_type('group'), 'facet label') or _('Groups')

    default_facet_titles = {
        'organization': org_label,
        'groups': group_label,
        'tags': _('Tags'),
        'res_format': _('Formats'),
    }

    for facet in h.facets():
        if facet in default_facet_titles:
            facets[facet] = default_facet_titles[facet]
        else:
            facets[facet] = facet

    # Facet titles
    for plugin in plugins.PluginImplementations(plugins.IFacets):
        facets = plugin.dataset_facets(facets, package_type)

    extra_vars[u'facet_titles'] = facets
    data_dict: dict[str, Any] = {
        'q': q,
        'fq': fq.strip(),
        'facet.field': list(facets.keys()),
        'rows': limit,
        'start': (page - 1) * limit,
        'sort': sort_by,
        'extras': search_extras,
        'include_private': config.get('ckan.search.default_include_private'),
    }
    try:
        package_search = get_action('package_search')
        query = package_search(context, data_dict)

        extra_vars['sort_by_selected'] = query['sort']
        extra_vars['page'] = Page(
            collection=query['results'],
            page=page,
            url=pager_url,
            item_count=query['count'],
            items_per_page=limit
        )
        extra_vars['search_facets'] = query['search_facets']
        extra_vars['page'].items = query['results']
    except SearchQueryError as se:
        # User's search parameters are invalid, in such a way that is not
        # achievable with the web interface, so return a proper error to
        # discourage spiders which are the main cause of this.
        log.info('Dataset search query rejected: %r', se.args)
        base.abort(
            400,
            _('Invalid search query: {error_message}')
            .format(error_message=str(se))
        )
    except SearchError as se:
        # May be bad input from the user, but may also be more serious like
        # bad code causing a SOLR syntax error, or a problem connecting to
        # SOLR
        log.error('Dataset search error: %r', se.args)
        extra_vars['query_error'] = True
        extra_vars['search_facets'] = {}
        extra_vars['page'] = Page(collection=[])

    # FIXME: try to avoid using global variables
    g.search_facets_limits = {}
    default_limit: int = config.get('search.facets.default')
    for facet in cast(Iterable[str], extra_vars['search_facets'].keys()):
        try:
            limit = int(request.args.get('_%s_limit' % facet, default_limit))
        except ValueError:
            base.abort(400, _('Parameter u"{parameter_name}" is not an integer').format(parameter_name='_%s_limit' % facet))
        g.search_facets_limits[facet] = limit

    _setup_template_variables(context, {}, package_type=package_type)

    extra_vars['dataset_type'] = package_type

    # TODO: remove
    for key, value in extra_vars.items():
        setattr(g, key, value)
    pkg_template = _get_pkg_template('search_template', package_type)
    return base.render(pkg_template, extra_vars)


def resources(package_type: str, id: str) -> Union[Response, str]:
    context = cast(Context, {
        'model': model,
        'session': model.Session,
        'user': current_user.name,
        'for_view': True,
        'auth_user_obj': current_user
    })
    data_dict: dict[str, Any] = {'id': id, 'include_tracking': True}

    try:
        check_access_to_package(context, {"id": id})
        check_access('package_update', context, data_dict)
    except NotFound:
        return base.abort(404, _('Dataset not found'))
    except NotAuthorized:
        return base.abort(
            403,
            _('User %r not authorized to edit %s') % (current_user.name, id)
        )
    # check if package exists
    try:
        package_show = get_action('package_show')
        pkg_dict = package_show(context, data_dict)
        pkg = context['package']
    except (NotFound, NotAuthorized):
        return base.abort(404, _(u'Dataset not found'))

    package_type = pkg_dict['type'] or 'dataset'
    _setup_template_variables(context, {u'id': id}, package_type=package_type)

    # TODO: remove
    g.pkg_dict = pkg_dict
    g.pkg = pkg

    return base.render(
        'package/resources.html', {
            'dataset_type': package_type,
            'pkg_dict': pkg_dict,
            'pkg': pkg
        }
    )


def check_access_to_package(context: Context, data_dict: DataDict):
    model = context['model']
    user_obj = context.get('auth_user_obj', current_user)
    if not user_obj or user_obj.is_anonymous or not user_obj.is_authenticated:
        raise NotAuthorized()
    if user_obj.sysadmin:
        return
    package_id = data_dict.get('id')
    package = model.Package
    package_member = model.PackageMember
    umember = aliased(model.Member)
    pmember = aliased(model.Member)
    pkg = package.get(package_id)
    if not pkg or pkg.state != "active":
        raise NotFound()
    if not pkg.private:
        return

    pmember_query = _select([package_member.package_id]).select_from(package_member).filter(package_member.package_id == pkg.id)
    gmember_query = _select([pmember.table_id]).select_from(pmember)\
            .join(umember, _and_(pmember.group_id == umember.group_id, pmember.state == 'active', pmember.table_name == 'package', pmember.capacity == 'organization', pmember.table_id == pkg.id))\
            .filter(_and_(umember.table_name == 'user', umember.state == 'active', umember.table_id == user_obj.id))

    query = _select([package.id])\
        .select_from(package)\
        .filter(_or_(pmember_query.exists(), gmember_query.exists()))
    results = {x for x in query.execute()}
    if not results:
        raise NotAuthorized()

def read(package_type: str, id: str) -> Union[Response, str]:
    context = cast(Context, {
        'model': model,
        'session': model.Session,
        'user': current_user.name,
        'for_view': True,
        'auth_user_obj': current_user
    })
    data_dict = {'id': id, 'include_tracking': True}

    # check if package exists
    try:
        check_access_to_package(context, {"id": id})
        package_show = get_action('package_show')
        pkg_dict = package_show(context, data_dict)
        pkg = context['package']
    except NotFound:
        return base.abort(404, _('Dataset not found or you have no permission to view it'))
    except NotAuthorized:
        if config.get('ckan.auth.reveal_private_datasets'):
            if current_user.is_authenticated:
                return base.abort(403, _('Unauthorized to read package %s') % id)
            else:
                return h.redirect_to("user.login", came_from=h.url_for('{}.read'.format(package_type), id=id))
        return base.abort(404, _('Dataset not found or you have no permission to view it'))

    g.pkg_dict = pkg_dict
    g.pkg = pkg

    if plugins.plugin_loaded("activity"):
        activity_id = request.args.get("activity_id")
        if activity_id:
            return h.redirect_to("activity.package_history", id=id, activity_id=activity_id)

    # if the user specified a package id, redirect to the package name
    if data_dict['id'] == pkg_dict['id'] and \
            data_dict['id'] != pkg_dict['name']:
        return h.redirect_to('{}.read'.format(package_type), id=pkg_dict['name'])

    # can the resources be previewed?
    for resource in pkg_dict['resources']:
        resource_view_list = get_action('resource_view_list')
        resource_views = resource_view_list(context, {'id': resource['id']})
        resource['has_views'] = len(resource_views) > 0

    package_type = pkg_dict['type'] or package_type
    _setup_template_variables(context, {'id': id}, package_type=package_type)

    template = _get_pkg_template('read_template', package_type)
    try:
        return base.render(
            template, {
                'dataset_type': package_type,
                'pkg_dict': pkg_dict,
                'pkg': pkg,
            }
        )
    except TemplateNotFound as e:
        msg = _(
            "Viewing datasets of type \"{package_type}\" is "
            "not supported ({file_!r}).".format(package_type=package_type, file_=e.message)
        )
        return base.abort(404, msg)


class CreateView(MethodView):
    def _is_save(self) -> bool:
        return u'save' in request.form

    def _prepare(self) -> Context:  # noqa

        context = cast(Context, {
            u'model': model,
            u'session': model.Session,
            u'user': current_user.name,
            u'auth_user_obj': current_user,
            u'save': self._is_save()
        })
        try:
            check_access(u'package_create', context)
        except NotAuthorized:
            return base.abort(403, _(u'Unauthorized to create a package'))
        return context

    def post(self, package_type: str) -> Union[Response, str]:
        # The staged add dataset used the new functionality when the dataset is
        # partially created so we need to know if we actually are updating or
        # this is a real new.
        context = self._prepare()
        is_an_update = False
        ckan_phase = request.form.get(u'_ckan_phase')
        try:
            data_dict = clean_dict(
                dict_fns.unflatten(tuplize_dict(parse_params(request.form)))
            )
        except dict_fns.DataError:
            return base.abort(400, _(u'Integrity Error'))
        try:
            if ckan_phase:
                # prevent clearing of groups etc
                context[u'allow_partial_update'] = True
                # sort the tags
                if u'tag_string' in data_dict:
                    data_dict[u'tags'] = _tag_string_to_list(
                        data_dict[u'tag_string']
                    )
                if data_dict.get(u'pkg_name'):
                    is_an_update = True
                    # This is actually an update not a save
                    data_dict[u'id'] = data_dict[u'pkg_name']
                    del data_dict[u'pkg_name']
                    # don't change the dataset state
                    data_dict[u'state'] = u'draft'
                    # this is actually an edit not a save
                    pkg_dict = get_action(u'package_update')(
                        context, data_dict
                    )

                    # redirect to add dataset resources
                    url = h.url_for(
                        u'{}_resource.new'.format(package_type),
                        id=pkg_dict[u'name']
                    )
                    return h.redirect_to(url)
                # Make sure we don't index this dataset
                if request.form[u'save'] not in [
                    u'go-resource', u'go-metadata'
                ]:
                    data_dict[u'state'] = u'draft'
                # allow the state to be changed
                context[u'allow_state_change'] = True

            data_dict[u'type'] = package_type
            pkg_dict = get_action(u'package_create')(context, data_dict)

            create_on_ui_requires_resources = config.get(
                'ckan.dataset.create_on_ui_requires_resources'
            )
            if ckan_phase:
                if create_on_ui_requires_resources:
                    # redirect to add dataset resources if
                    # create_on_ui_requires_resources is set to true
                    url = h.url_for(
                        u'{}_resource.new'.format(package_type),
                        id=pkg_dict[u'name']
                    )
                    return h.redirect_to(url)

                get_action(u'package_update')(
                    cast(Context, dict(context, allow_state_change=True)),
                    dict(pkg_dict, state=u'active')
                )
                return h.redirect_to(
                    u'{}.read'.format(package_type),
                    id=pkg_dict["id"]
                )

            return _form_save_redirect(
                pkg_dict[u'name'], u'new', package_type=package_type
            )
        except NotAuthorized:
            return base.abort(403, _(u'Unauthorized to read package'))
        except NotFound:
            return base.abort(404, _(u'Dataset not found'))
        except SearchIndexError as e:
            try:
                exc_str = str(repr(e.args))
            except Exception:  # We don't like bare excepts
                exc_str = str(str(e))
            return base.abort(
                500,
                _(u'Unable to add package to search index.') + exc_str
            )
        except ValidationError as e:
            errors = e.error_dict
            error_summary = e.error_summary
            if is_an_update:
                # we need to get the state of the dataset to show the stage we
                # are on.
                pkg_dict = get_action(u'package_show')(context, data_dict)
                data_dict[u'state'] = pkg_dict[u'state']
                return EditView().get(
                    package_type,
                    data_dict[u'id'],
                    data_dict,
                    errors,
                    error_summary
                )
            data_dict[u'state'] = u'none'
            return self.get(package_type, data_dict, errors, error_summary)

    def get(self,
            package_type: str,
            data: Optional[dict[str, Any]] = None,
            errors: Optional[dict[str, Any]] = None,
            error_summary: Optional[dict[str, Any]] = None) -> str:
        context = self._prepare()
        if data and u'type' in data:
            package_type = data[u'type']

        data = data or clean_dict(
            dict_fns.unflatten(
                tuplize_dict(
                    parse_params(request.args, ignore_keys=CACHE_PARAMETERS)
                )
            )
        )
        resources_json = h.dump_json(data.get(u'resources', []))
        # convert tags if not supplied in data
        if data and not data.get(u'tag_string'):
            data[u'tag_string'] = u', '.join(
                h.dict_list_reduce(data.get(u'tags', {}), u'name')
            )

        errors = errors or {}
        error_summary = error_summary or {}
        # in the phased add dataset we need to know that
        # we have already completed stage 1
        stage = [u'active']
        if data.get(u'state', u'').startswith(u'draft'):
            stage = [u'active', u'complete']

        # if we are creating from a group then this allows the group to be
        # set automatically
        data[
            u'group_id'
        ] = request.args.get(u'group') or request.args.get(u'groups__0__id')

        form_snippet = _get_pkg_template(
            u'package_form', package_type=package_type
        )
        form_vars: dict[str, Any] = {
            u'data': data,
            u'errors': errors,
            u'error_summary': error_summary,
            u'action': u'new',
            u'stage': stage,
            u'dataset_type': package_type,
            u'form_style': u'new'
        }
        errors_json = h.dump_json(errors)

        # TODO: remove
        g.resources_json = resources_json
        g.errors_json = errors_json

        _setup_template_variables(context, {}, package_type=package_type)

        new_template = _get_pkg_template(u'new_template', package_type)
        return base.render(
            new_template,
            extra_vars={
                u'form_vars': form_vars,
                u'form_snippet': form_snippet,
                u'dataset_type': package_type,
                u'resources_json': resources_json,
                u'form_snippet': form_snippet,
                u'errors_json': errors_json
            }
        )


class EditView(MethodView):
    def _prepare(self) -> Context:
        context = cast(Context, {
            'model': model,
            'session': model.Session,
            'user': current_user.name,
            'auth_user_obj': current_user,
            'save': u'save' in request.form
        })
        return context

    def post(self, package_type: str, id: str) -> Union[Response, str]:
        context = self._prepare()
        package_type = _get_package_type(id) or package_type
        try:
            data_dict = clean_dict(
                dict_fns.unflatten(tuplize_dict(parse_params(request.form)))
            )
        except dict_fns.DataError:
            return base.abort(400, _('Integrity Error'))
        try:
            check_access_to_package(context, {"id": id})
            if '_ckan_phase' in data_dict:
                # we allow partial updates to not destroy existing resources
                context[u'allow_partial_update'] = True
                if 'tag_string' in data_dict:
                    data_dict[u'tags'] = _tag_string_to_list(
                        data_dict[u'tag_string']
                    )
                del data_dict[u'_ckan_phase']
                del data_dict[u'save']
            data_dict['id'] = id
            pkg_dict = get_action(u'package_update')(context, data_dict)

            return _form_save_redirect(
                pkg_dict[u'name'], u'edit', package_type=package_type
            )
        except NotAuthorized:
            return base.abort(403, _(u'Unauthorized to read package %s') % id)
        except NotFound:
            return base.abort(404, _(u'Dataset not found'))
        except SearchIndexError as e:
            try:
                exc_str = str(repr(e.args))
            except Exception:  # We don't like bare excepts
                exc_str = str(str(e))
            return base.abort(
                500,
                _(u'Unable to update search index.') + exc_str
            )
        except ValidationError as e:
            errors = e.error_dict
            error_summary = e.error_summary
            return self.get(package_type, id, data_dict, errors, error_summary)

    def get(self,
            package_type: str,
            id: str,
            data: Optional[dict[str, Any]] = None,
            errors: Optional[dict[str, Any]] = None,
            error_summary: Optional[dict[str, Any]] = None
            ) -> Union[Response, str]:
        context = self._prepare()
        package_type = _get_package_type(id) or package_type
        try:
            view_context = context.copy()
            view_context['for_view'] = True
            pkg_dict = get_action(u'package_show')(
                view_context, {u'id': id})
            context[u'for_edit'] = True
            old_data = get_action(u'package_show')(context, {u'id': id})
            # old data is from the database and data is passed from the
            # user if there is a validation error. Use users data if there.
            if data:
                old_data.update(data)
            data = old_data
        except (NotFound, NotAuthorized):
            return base.abort(404, _(u'Dataset not found'))
        assert data is not None
        # are we doing a multiphase add?
        if data.get(u'state', u'').startswith(u'draft'):
            g.form_action = h.url_for(u'{}.new'.format(package_type))
            g.form_style = u'new'

            return CreateView().get(
                package_type,
                data=data,
                errors=errors,
                error_summary=error_summary
            )

        pkg = context.get(u"package")
        resources_json = h.dump_json(data.get(u'resources', []))
        user = current_user.name
        try:
            check_access(u'package_update', context)
        except NotAuthorized:
            return base.abort(
                403,
                _(u'User %r not authorized to edit %s') % (user, id)
            )
        # convert tags if not supplied in data
        if data and not data.get(u'tag_string'):
            data[u'tag_string'] = u', '.join(
                h.dict_list_reduce(pkg_dict.get(u'tags', {}), u'name')
            )
        errors = errors or {}
        form_snippet = _get_pkg_template(
            u'package_form', package_type=package_type
        )
        form_vars: dict[str, Any] = {
            u'data': data,
            u'errors': errors,
            u'error_summary': error_summary,
            u'action': u'edit',
            u'dataset_type': package_type,
            u'form_style': u'edit'
        }
        errors_json = h.dump_json(errors)

        # TODO: remove
        g.pkg = pkg
        g.resources_json = resources_json
        g.errors_json = errors_json

        _setup_template_variables(
            context, {u'id': id}, package_type=package_type
        )

        # we have already completed stage 1
        form_vars[u'stage'] = [u'active']
        if data.get(u'state', u'').startswith(u'draft'):
            form_vars[u'stage'] = [u'active', u'complete']

        edit_template = _get_pkg_template(u'edit_template', package_type)
        return base.render(
            edit_template,
            extra_vars={
                u'form_vars': form_vars,
                u'form_snippet': form_snippet,
                u'dataset_type': package_type,
                u'pkg_dict': pkg_dict,
                u'pkg': pkg,
                u'resources_json': resources_json,
                u'form_snippet': form_snippet,
                u'errors_json': errors_json
            }
        )


class DeleteView(MethodView):
    def _prepare(self) -> Context:
        context = cast(Context, {
            'model': model,
            'session': model.Session,
            'user': current_user.name,
            'auth_user_obj': current_user
        })
        return context

    def post(self, package_type: str, id: str) -> Response:
        if 'cancel' in request.form:
            return h.redirect_to('{}.edit'.format(package_type), id=id)
        context = self._prepare()
        try:
            check_access_to_package(context, {"id": id})
            package_delete = get_action(u'package_delete')
            package_delete(context, {'id': id})
        except NotFound:
            return base.abort(404, _('Dataset not found'))
        except NotAuthorized:
            return base.abort(
                403,
                _('Unauthorized to delete package %s') % u''
            )

        h.flash_notice(_('Dataset has been deleted.'))
        return h.redirect_to(package_type + '.search')

    def get(self, package_type: str, id: str) -> Union[Response, str]:
        context = self._prepare()
        try:
            check_access_to_package(context, {"id": id})
            package_show = get_action('package_show')
            pkg_dict = package_show(context, {'id': id})
        except NotFound:
            return base.abort(404, _('Dataset not found'))
        except NotAuthorized:
            return base.abort(
                403,
                _('Unauthorized to delete package %s') % ''
            )

        dataset_type = pkg_dict['type'] or package_type

        # TODO: remove
        g.pkg_dict = pkg_dict

        return base.render(
            'package/confirm_delete.html', {
                'pkg_dict': pkg_dict,
                'dataset_type': dataset_type
            }
        )


def follow(package_type: str, id: str) -> Response:
    """Start following this dataset.
    """
    context = cast(Context, {
        'model': model,
        'session': model.Session,
        'user': current_user.name,
        'auth_user_obj': current_user
    })
    data_dict = {'id': id}
    try:
        check_access_to_package(context, {"id": id})
        follow_dataset = get_action('follow_dataset')
        follow_dataset(context, data_dict)
        package_show = get_action('package_show')
        package_dict = package_show(context, data_dict)
        id = package_dict['name']
    except ValidationError as e:
        error_message = (e.message or e.error_summary or e.error_dict)
        h.flash_error(error_message)
    except NotAuthorized as e:
        h.flash_error(e.message)
    else:
        h.flash_success(
            _("You are now following {0}").format(package_dict['title'])
        )
    return h.redirect_to('{}.read'.format(package_type), id=id)


def unfollow(package_type: str, id: str) -> Union[Response, str]:
    """Stop following this dataset.
    """
    context = cast(Context, {
        'model': model,
        'session': model.Session,
        'user': current_user.name,
        'auth_user_obj': current_user
    })
    data_dict = {'id': id}
    try:
        check_access_to_package(context, {"id": id})
        unfollow_dataset = get_action('unfollow_dataset')
        unfollow_dataset(context, data_dict)
        package_show = get_action('package_show')
        package_dict = package_show(context, data_dict)
        id = package_dict['name']
    except ValidationError as e:
        error_message = (e.message or e.error_summary or e.error_dict)
        h.flash_error(error_message)
    except NotFound as e:
        error_message = e.message or ''
        base.abort(404, _(error_message))
    except NotAuthorized as e:
        error_message = e.message or ''
        base.abort(403, _(error_message))
    else:
        h.flash_success(_("You are no longer following {0}").format(package_dict['title']))

    return h.redirect_to('{}.read'.format(package_type), id=id)


def followers(package_type: str,
              id: Optional[str] = None) -> Union[Response, str]:
    context = cast(Context, {
        'model': model,
        'session': model.Session,
        'user': current_user.name,
        'for_view': True,
        'auth_user_obj': current_user
    })

    data_dict = {'id': id}
    try:
        check_access_to_package(context, {"id": id})
        package_show = get_action('package_show')
        pkg_dict = package_show(context, data_dict)
        pkg = context['package']
        dataset_follower_list = get_action('dataset_follower_list')
        followers = dataset_follower_list(context, {'id': id})
        dataset_type = pkg.type or package_type
    except NotFound:
        return base.abort(404, _('Dataset not found'))
    except NotAuthorized:
        return base.abort(403, _('Unauthorized to read package %s') % id)

    # TODO: remove
    g.pkg_dict = pkg_dict
    g.pkg = pkg
    g.followers = followers

    return base.render(
        'package/followers.html', {
            'dataset_type': dataset_type,
            'pkg_dict': pkg_dict,
            'pkg': pkg,
            'followers': followers
        }
    )


class GroupView(MethodView):
    def _prepare(self, id: str) -> tuple[Context, dict[str, Any]]:
        context = cast(Context, {
            'model': model,
            'session': model.Session,
            'user': current_user.name,
            'for_view': True,
            'auth_user_obj': current_user,
            'use_cache': False
        })

        try:
            check_access_to_package(context, {"id": id})
            package_show = get_action('package_show')
            pkg_dict = package_show(context, {'id': id})
        except (NotFound, NotAuthorized):
            return base.abort(404, _('Dataset not found'))
        return context, pkg_dict

    def post(self, package_type: str, id: str) -> Response:
        context = self._prepare(id)[0]
        new_group = request.form.get('group_added')
        if new_group:
            data_dict = {
                "id": new_group,
                "object": id,
                "object_type": u'package',
                "capacity": u'public'
            }
            try:
                member_create = get_action(u'member_create')
                member_create(context, data_dict)
            except NotFound:
                return base.abort(404, _('Group not found'))

        removed_group = None
        for param in request.form:
            if param.startswith('group_remove'):
                removed_group = param.split('.')[-1]
                break
        if removed_group:
            data_dict = {
                "id": removed_group,
                "object": id,
                "object_type": u'package'
            }

            try:
                member_delete = get_action('member_delete')
                member_delete(context, data_dict)
            except NotFound:
                return base.abort(404, _('Group not found'))
        return h.redirect_to('{}.groups'.format(package_type), id=id)

    def get(self, package_type: str, id: str) -> str:
        context, pkg_dict = self._prepare(id)
        dataset_type = pkg_dict['type'] or package_type
        context['is_member'] = True
        group_list_authz = get_action('group_list_authz')
        users_groups = group_list_authz(context, {'id': id})

        pkg_group_ids = set(
            group['id'] for group in pkg_dict.get('groups', [])
        )

        user_group_ids = set(group['id'] for group in users_groups)

        group_dropdown = [[group['id'], group['display_name']]
                          for group in users_groups
                          if group['id'] not in pkg_group_ids]

        for group in pkg_dict.get('groups', []):
            group['user_member'] = group['id'] in user_group_ids

        # TODO: remove
        g.pkg_dict = pkg_dict
        g.group_dropdown = group_dropdown
        return base.render(
            'package/group_list.html', {
                'dataset_type': dataset_type,
                'pkg_dict': pkg_dict,
                'group_dropdown': group_dropdown
            }
        )
class OrganizationView(MethodView):
    def _prepare(self, id: str) -> tuple[Context, dict[str, Any]]:
        context = cast(Context, {
            'model': model,
            'session': model.Session,
            'user': current_user.name,
            'for_view': True,
            'auth_user_obj': current_user,
            'use_cache': False
        })

        try:
            check_access_to_package(context, {"id": id})
            package_show = get_action('package_show')
            pkg_dict = package_show(context, {'id': id})
        except (NotFound, NotAuthorized):
            return base.abort(404, _('Dataset not found'))
        return context, pkg_dict

    def post(self, package_type: str, id: str) -> Response:
        context = self._prepare(id)[0]
        new_group = request.form.get('group_added')
        if new_group:
            data_dict = {
                "id": new_group,
                "object": id,
                "object_type": 'package',
                "capacity": 'organization'
            }
            try:
                member_create = get_action('member_create')
                member_create(context, data_dict)
            except NotFound:
                return base.abort(404, _(u'Organization not found'))

        removed_group = None
        for param in request.form:
            if param.startswith(u'group_remove'):
                removed_group = param.split(u'.')[-1]
                break
        if removed_group:
            data_dict = {
                u"id": removed_group,
                u"object": id,
                u"object_type": u'package'
            }

            try:
                member_delete = get_action(u'member_delete')
                member_delete(context, data_dict)
            except NotFound:
                return base.abort(404, _('Organization not found'))
        return h.redirect_to('{}.organizations'.format(package_type), id=id)

    def get(self, package_type: str, id: str) -> str:
        context, pkg_dict = self._prepare(id)
        dataset_type = pkg_dict['type'] or package_type
        context['is_member'] = True
        organization_list_for_user = get_action('organization_list_for_user')
        user = context['auth_user_obj']
        users_orgs = organization_list_for_user(context, {'id': user.id}) if user and user.is_authenticated else []
        package_orgs = pkg_dict.get('orgs', [])
        pkg_group_ids = set(group['id'] for group in package_orgs)
        user_org_ids = set(group['id'] for group in users_orgs)
        group_dropdown = [[group['id'], group['display_name']]
                          for group in users_orgs
                          if group['id'] not in pkg_group_ids]

        owner_org = pkg_dict['owner_org']
        for org in package_orgs:
            org_id = org['id']
            user_member = org_id in user_org_ids and org_id != owner_org
            org['user_member'] = user_member

        # TODO: remove
        g.pkg_dict = pkg_dict
        g.group_dropdown = group_dropdown
        return base.render(
            'package/org_list.html', {
                'dataset_type': dataset_type,
                'pkg_dict': pkg_dict,
                'group_dropdown': group_dropdown
            }
        )

def collaborators_read(package_type: str, id: str) -> Union[Response, str]:  # noqa
    context = cast(Context, {'model': model, 'user': current_user.name})
    data_dict = {'id': id}

    try:
        check_access_to_package(context, {"id": id})
        check_access('package_collaborator_list', context, data_dict)
        # needed to ckan_extend package/edit_base.html
        package_show = get_action('package_show')
        pkg_dict = package_show(context, data_dict)
    except NotAuthorized:
        message = _('Unauthorized to read collaborators {}').format(id)
        return base.abort(401, message)
    except NotFound:
        return base.abort(404, _('Dataset not found'))

    return base.render('package/collaborators/collaborators.html', {'pkg_dict': pkg_dict})


def collaborator_delete(package_type: str,
                        id: str, user_id: str) -> Union[Response, str]:  # noqa
    context: Context = {'user': current_user.name}

    if 'cancel' in request.form:
        return h.redirect_to('{}.collaborators_read'
                             .format(package_type), id=id)

    try:
        check_access_to_package(context, {"id": id})
        if request.method == 'POST':
            _log_collaborator_delete(context, id, user_id, current_user.name)
            get_action('package_collaborator_delete')(context, {
                'id': id,
                'user_id': user_id
            })
        user_show = logic.get_action('user_show')
        user_dict = user_show(context, {'id': user_id})
    except NotAuthorized:
        message = _('Unauthorized to delete collaborators {}').format(id)
        return base.abort(401, _(message))
    except NotFound as e:
        return base.abort(404, _(e.message))

    if request.method == 'POST':
        h.flash_success(_('User removed from collaborators'))

        return h.redirect_to('dataset.collaborators_read', id=id)

    # TODO: Remove
    # ckan 2.9: Adding variables that were removed from c object for
    # compatibility with templates in existing extensions
    g.user_dict = user_dict
    g.user_id = user_id
    g.package_id = id

    extra_vars = {
        u"user_id": user_id,
        u"user_dict": user_dict,
        u"package_id": id,
        u"package_type": package_type
    }
    return base.render(
        u'package/collaborators/confirm_delete.html', extra_vars)

def _log_collaborator_delete(context, package_id: str, user_id: str, user_initiator_name: str):
    role = None

    try:
        check_access_to_package(context, {"id": package_id})
        package_show = get_action('package_show')
        pkg_dict = package_show(context, {'id': package_id})
        package_collaborator_list = get_action('package_collaborator_list')
        collaborators = package_collaborator_list(context, {'id': package_id})
        user = next(c for c in collaborators if c['user_id'] == user_id)
        if user:
            role = user['capacity']
        user_show = logic.get_action('user_show')
        user_dict = user_show(context, {'id': user_id})
        username = user_dict['name']
        log.info(
            f'package_collaborator_delete: '
            f'username = {username}, '
            f'role = {_(role.title())}, '
            f'package_id = {package_id}, '
            f'package_name = {pkg_dict[u"name"]}, '
            f'user_initiator_name = {user_initiator_name}'
        )
    except Exception as e:
        log.error('package_collaborator_delete error: %r', e.args)

class CollaboratorEditView(MethodView):

    def post(self, package_type: str, id: str) -> Response:  # noqa
        context = cast(Context, {'model': model, 'user': current_user.name})

        try:
            check_access_to_package(context, {"id": id})
            form_dict = logic.clean_dict(
                dict_fns.unflatten(
                    logic.tuplize_dict(
                        logic.parse_params(request.form))))

            user_show = get_action('user_show')
            user = user_show(
                context, {'id': form_dict['username']}
            )

            data_dict: dict[str, Any] = {
                'id': id,
                'user_id': user['id'],
                'capacity': form_dict['capacity']
            }

            package_collaborator_create = get_action(u'package_collaborator_create')
            package_collaborator_create(context, data_dict)
            self._log_package_collaborator_create(id, data_dict, form_dict)

        except dict_fns.DataError:
            return base.abort(400, _('Integrity Error'))
        except NotAuthorized:
            message = _('Unauthorized to edit collaborators {}').format(id)
            return base.abort(401, _(message))
        except NotFound:
            h.flash_error(_('User not found'))
            return h.redirect_to('dataset.new_collaborator', id=id)
        except ValidationError as e:
            h.flash_error(e.error_summary)
            return h.redirect_to('dataset.new_collaborator', id=id)
        else:
            h.flash_success(_('User added to collaborators'))

        return h.redirect_to('dataset.collaborators_read', id=id)

    def _log_package_collaborator_create(self, package_id: str, data_dict, form_dict):
        try:
            log.info(
                f'package_collaborator_create: '
                f'username = {form_dict.get(u"username")}, '
                f'role = {_(form_dict.get(u"capacity").title())}, '
                f'package_id = {package_id}, '
                f'package_name = {data_dict.get(u"id")}'
            )
        except Exception as e:
            log.error(u'package_collaborator_create error: %r', e.args)

    def get(self, package_type: str, id: str) -> Union[Response, str]:  # noqa
        context = cast(Context, {'model': model, 'user': current_user.name})
        data_dict = {'id': id}

        try:
            check_access_to_package(context, {"id": id})
            check_access('package_collaborator_list', context, data_dict)
            # needed to ckan_extend package/edit_base.html
            package_show = get_action('package_show')
            pkg_dict = package_show(context, data_dict)
        except NotAuthorized:
            message = 'Unauthorized to read collaborators {}'.format(id)
            return base.abort(401, _(message))
        except NotFound:
            return base.abort(404, _('Resource not found'))

        user = request.args.get('user_id')
        user_capacity = 'member'

        if user:
            package_collaborator_list = get_action('package_collaborator_list')
            collaborators = package_collaborator_list(context, data_dict)
            for c in collaborators:
                if c['user_id'] == user:
                    user_capacity = c['capacity']
            user_show = get_action('user_show')
            user = user_show(context, {u'id': user})

        capacities: list[dict[str, str]] = []
        if authz.check_config_permission('allow_admin_collaborators'):
            capacities.append({'name': _('admin'), 'value': 'admin'})
        capacities.extend([
            {'name': _('editor'), 'value': 'editor'},
            {'name': _('member'), 'value': 'member'}
        ])
        log.info(f"Collaborators: {capacities}")
        extra_vars: dict[str, Any] = {
            'capacities': capacities,
            'user_capacity': user_capacity,
            'user': user,
            'pkg_dict': pkg_dict,
        }

        return base.render(
            'package/collaborators/collaborator_new.html', extra_vars)


def register_dataset_plugin_rules(blueprint: Blueprint):
    blueprint.add_url_rule('/', view_func=search, strict_slashes=False)
    blueprint.add_url_rule('/new', view_func=CreateView.as_view('new'))
    blueprint.add_url_rule('/<id>', view_func=read)
    blueprint.add_url_rule('/resources/<id>', view_func=resources)
    blueprint.add_url_rule('/edit/<id>', view_func=EditView.as_view('edit'))
    blueprint.add_url_rule('/delete/<id>', view_func=DeleteView.as_view('delete'))
    blueprint.add_url_rule('/follow/<id>', view_func=follow, methods=('POST', ))
    blueprint.add_url_rule('/unfollow/<id>', view_func=unfollow, methods=('POST', ))
    blueprint.add_url_rule('/followers/<id>', view_func=followers)
    blueprint.add_url_rule('/groups/<id>', view_func=GroupView.as_view('groups'))
    blueprint.add_url_rule( '/organizations/<id>', view_func=OrganizationView.as_view('organizations'))

    if authz.check_config_permission('allow_dataset_collaborators'):
        blueprint.add_url_rule(
            rule='/collaborators/<id>',
            view_func=collaborators_read,
            methods=['GET', ]
        )

        blueprint.add_url_rule(
            rule='/collaborators/<id>/new',
            view_func=CollaboratorEditView.as_view('new_collaborator'),
            methods=['GET', 'POST', ]
        )

        blueprint.add_url_rule(
            rule='/collaborators/<id>/delete/<user_id>',
            view_func=collaborator_delete, methods=['POST', 'GET']
        )


register_dataset_plugin_rules(dataset)
# remove this when we improve blueprint registration to be explicit:
dataset.auto_register = False  # type: ignore
