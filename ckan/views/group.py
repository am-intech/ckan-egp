# encoding: utf-8
from __future__ import annotations

import logging
import re
from collections import OrderedDict
from typing import Any, Optional, Union, cast

import sqlalchemy
from typing_extensions import Literal

from urllib.parse import urlencode

import ckan.lib.base as base
from ckan.lib.helpers import helper_functions as h
from ckan.lib.helpers import Page
import ckan.lib.navl.dictization_functions as dict_fns
from ckan.logic import (
    get_action,
    NotAuthorized,
    NotFound,
    check_access,
    ValidationError,
    tuplize_dict,
    clean_dict,
    parse_params,
)
import ckan.lib.search as search
import ckan.model as model
import ckan.authz as authz
import ckan.lib.plugins as lib_plugins
import ckan.plugins as plugins
from ckan.common import g, config, request, current_user, _, ungettext, session
from ckan.views.home import CACHE_PARAMETERS
from ckan.views.dataset import _get_search_details

from flask import Blueprint
from flask.views import MethodView
from flask.wrappers import Response
from ckan.types import Action, Context, DataDict, Schema

log = logging.getLogger(__name__)
_select = sqlalchemy.select
_and_ = sqlalchemy.and_

lookup_group_plugin = lib_plugins.lookup_group_plugin
lookup_group_controller = lib_plugins.lookup_group_controller

is_org = False


def check_access_to_group(context: Context, data_dict: DataDict):
    model = context["model"]
    user_obj = context.get("auth_user_obj", current_user)
    if not user_obj or user_obj.is_anonymous or not user_obj.is_authenticated:
        raise NotAuthorized()
    if user_obj.sysadmin:
        return
    group_id = data_dict.get("id")
    group = model.Group.get(group_id)
    if not group or group.state != "active":
        raise NotFound()
    member = model.Member

    query = (
        _select([member.group_id])
        .select_from(member)
        .filter(
            _and_(
                member.table_name == "user",
                member.state == "active",
                member.table_id == user_obj.id,
            )
        )
    )
    results = {x for x in query.execute()}
    if not results:
        raise NotAuthorized()


def _get_group_template(
    template_type: str, group_type: Optional[str] = None
) -> str:
    group_plugin = lookup_group_plugin(group_type)
    method = getattr(group_plugin, template_type)
    try:
        return method(group_type)
    except TypeError as err:
        if "takes 1" not in str(err) and "takes exactly 1" not in str(err):
            raise
        return method()


def _db_to_form_schema(group_type: Optional[str] = None) -> Schema:
    """This is an interface to manipulate data from the database
    into a format suitable for the form (optional)"""
    return lookup_group_plugin(group_type).db_to_form_schema()


def _setup_template_variables(
    context: Context, data_dict: DataDict, group_type: Optional[str] = None
) -> None:
    if "type" not in data_dict:
        data_dict["type"] = group_type
    return lookup_group_plugin(group_type).setup_template_variables(
        context, data_dict
    )


def _replace_group_org(string: str) -> str:
    """substitute organization for group if this is an org"""
    if is_org:
        return re.sub("^group", "organization", string)
    return string


def _action(action_name: str) -> Action:
    """select the correct group/org action"""
    return get_action(_replace_group_org(action_name))


def _check_access(action_name: str, *args: Any, **kw: Any) -> Literal[True]:
    """select the correct group/org check_access"""
    return check_access(_replace_group_org(action_name), *args, **kw)


def _guess_group_type(expecting_name: bool = False) -> str:
    """
    Guess the type of group from the URL.
    * The default url '/group/xyz' returns None
    * group_type is unicode
    * this handles the case where there is a prefix on the URL
      (such as /data/organization)
    """
    parts: list[str] = request.path.split("/")
    parts = [x for x in parts if x]

    idx = 0
    if expecting_name:
        idx = -1

    gt = parts[idx]

    return gt


def set_org(is_organization: bool) -> None:
    global is_org
    is_org = is_organization


def index(group_type: str, is_organization: bool) -> str:
    extra_vars: dict[str, Any] = {}
    set_org(is_organization)
    page = h.get_page_number(request.args) or 1
    items_per_page = config.get("ckan.datasets_per_page")

    context = cast(
        Context,
        {
            "model": model,
            "session": model.Session,
            "user": current_user.name,
            "for_view": True,
            "with_private": False,
        },
    )

    try:
        assert _check_access("site_read", context)
        assert _check_access("group_list", context)
    except NotAuthorized:
        base.abort(403, _("Not authorized to see this page"))

    q = request.args.get("q", "")
    sort_by = request.args.get("sort")

    # TODO: Remove
    # ckan 2.9: Adding variables that were removed from c object for
    # compatibility with templates in existing extensions
    g.q = q
    g.sort_by_selected = sort_by

    extra_vars["q"] = q
    extra_vars["sort_by_selected"] = sort_by

    # pass user info to context as needed to view private datasets of
    # orgs correctly
    if current_user.is_authenticated:
        context["user_id"] = current_user.id  # type: ignore
        context["user_is_admin"] = current_user.sysadmin  # type: ignore

    group_list = _action("group_list")
    data_dict_global_results: dict[str, Any] = {
        "all_fields": False,
        "q": q,
        "sort": sort_by,
        "type": group_type or "group",
    }
    try:
        global_results = group_list(context, data_dict_global_results)
    except ValidationError as e:
        if e.error_dict and e.error_dict.get("message"):
            msg: Any = e.error_dict["message"]
        else:
            msg = str(e)
        h.flash_error(msg)
        extra_vars["page"] = Page([], 0)
        extra_vars["group_type"] = group_type
        return base.render(
            _get_group_template("index_template", group_type), extra_vars
        )

    data_dict_page_results: dict[str, Any] = {
        "all_fields": True,
        "q": q,
        "sort": sort_by,
        "type": group_type or "group",
        "limit": items_per_page,
        "offset": items_per_page * (page - 1),
        "include_extras": True,
    }
    page_results = group_list(context, data_dict_page_results)

    extra_vars["page"] = Page(
        collection=global_results,
        page=page,
        url=h.pager_url,
        items_per_page=items_per_page,
    )

    extra_vars["page"].items = page_results
    extra_vars["group_type"] = group_type

    # TODO: Remove
    # ckan 2.9: Adding variables that were removed from c object for
    # compatibility with templates in existing extensions
    g.page = extra_vars["page"]
    return base.render(
        _get_group_template("index_template", group_type), extra_vars
    )


def _read(id: Optional[str], limit: int, group_type: str) -> dict[str, Any]:
    """This is common code used by both read and bulk_process"""
    extra_vars: dict[str, Any] = {}
    context = cast(
        Context,
        {
            "model": model,
            "session": model.Session,
            "user": current_user.name,
            "schema": _db_to_form_schema(group_type=group_type),
            "for_view": True,
            "extras_as_string": True,
        },
    )

    q = request.args.get("q", "")

    # TODO: Remove
    # ckan 2.9: Adding variables that were removed from c object for
    # compatibility with templates in existing extensions
    g.q = q

    # Search within group
    if g.group_dict.get("is_organization"):
        fq = ' owner_org:"%s"' % g.group_dict.get("id")
    else:
        fq = ' groups:"%s"' % g.group_dict.get("name")

    extra_vars["q"] = q

    g.description_formatted = h.render_markdown(
        g.group_dict.get("description")
    )

    context["return_query"] = True

    page = h.get_page_number(request.args)

    # most search operations should reset the page counter:
    params_nopage = [
        (k, v) for k, v in request.args.items(multi=True) if k != "page"
    ]
    sort_by = request.args.get("sort", None)

    def search_url(params: Any) -> str:
        action = (
            "bulk_process"
            if getattr(g, "action", "") == "bulk_process"
            else "read"
        )
        url = h.url_for(".".join([group_type, action]), id=id)
        params = [
            (k, v.encode("utf-8") if isinstance(v, str) else str(v))
            for k, v in params
        ]
        return url + "?" + urlencode(params)

    def remove_field(
        key: str, value: Optional[str] = None, replace: Optional[str] = None
    ):
        controller = lookup_group_controller(group_type)
        return h.remove_url_param(
            key,
            value=value,
            replace=replace,
            controller=controller,
            action="read",
            extras=dict(id=g.group_dict.get("name")),
        )

    extra_vars["remove_field"] = remove_field

    def pager_url(q: Any = None, page: Optional[int] = None):
        params: list[tuple[str, Any]] = list(params_nopage)
        params.append(("page", page))
        return search_url(params)

    details = _get_search_details()
    extra_vars["fields"] = details["fields"]
    extra_vars["fields_grouped"] = details["fields_grouped"]
    fq += details["fq"]
    search_extras = details["search_extras"]

    # TODO: Remove
    # ckan 2.9: Adding variables that were removed from c object for
    # compatibility with templates in existing extensions
    g.fields = extra_vars["fields"]
    g.fields_grouped = extra_vars["fields_grouped"]

    facets: "OrderedDict[str, str]" = OrderedDict()

    default_facet_titles = {
        "organization": _("Organizations."),
        "groups": _("Groups"),
        "tags": _("Tags"),
    }

    for facet in h.facets():
        if facet in default_facet_titles:
            facets[facet] = default_facet_titles[facet]
        # else:
        #     facets[facet] = facet

    # Facet titles
    facets = _update_facet_titles(facets, group_type)

    extra_vars["facet_titles"] = facets

    data_dict: dict[str, Any] = {
        "q": q,
        "fq": fq.replace("groups:", "organization:"),
        "include_private": True,
        "facet.field": list(facets.keys()),
        "rows": limit,
        "sort": sort_by,
        "start": (page - 1) * limit,
        "extras": search_extras,
    }

    context_ = cast(
        Context, dict((k, v) for (k, v) in context.items() if k != "schema")
    )
    try:
        log.info(f"Query groups: {data_dict}")
        package_search = get_action("package_search")
        query = package_search(context_, data_dict)
    except search.SearchError as se:
        log.error("Group search error: %r", se.args)
        extra_vars["query_error"] = True
        extra_vars["page"] = Page(collection=[])
    else:
        extra_vars["page"] = Page(
            collection=query["results"],
            page=page,
            url=pager_url,
            item_count=query["count"],
            items_per_page=limit,
        )

        # TODO: Remove
        # ckan 2.9: Adding variables that were removed from c object for
        # compatibility with templates in existing extensions
        g.group_dict["package_count"] = query["count"]

        extra_vars["search_facets"] = query["search_facets"]
        extra_vars["search_facets_limits"] = g.search_facets_limits = {}
        default_limit: int = config.get("search.facets.default")
        for facet in extra_vars["search_facets"].keys():
            limit = int(request.args.get("_%s_limit" % facet, default_limit))
            g.search_facets_limits[facet] = limit
        extra_vars["page"].items = query["results"]

        extra_vars["sort_by_selected"] = sort_by

    # TODO: Remove
    # ckan 2.9: Adding variables that were removed from c object for
    # compatibility with templates in existing extensions
    g.facet_titles = facets
    g.page = extra_vars["page"]

    extra_vars["group_type"] = group_type
    _setup_template_variables(context, {"id": id}, group_type=group_type)
    return extra_vars


def _update_facet_titles(
    facets: "OrderedDict[str, str]", group_type: str
) -> "OrderedDict[str, str]":
    for plugin in plugins.PluginImplementations(plugins.IFacets):
        facets = (
            plugin.group_facets(facets, group_type, None)
            if group_type == "group"
            else plugin.organization_facets(facets, group_type, None)
        )
    return facets


def _get_group_dict(id: str, group_type: str) -> dict[str, Any]:
    """returns the result of group_show action or aborts if there is a
    problem"""
    context = cast(
        Context,
        {
            "model": model,
            "session": model.Session,
            "user": current_user.name,
            "for_view": True,
        },
    )
    try:
        group_show = _action("group_show")
        return group_show(context, {"id": id, "include_datasets": False})
    except NotFound:
        base.abort(404, _("Group not found"))
    except NotAuthorized:
        base.abort(403, _("Not authorized to see this page"))


def read(
    group_type: str, is_organization: bool, id: Optional[str] = None
) -> Union[str, Response]:
    extra_vars = {}
    set_org(is_organization)
    context = cast(
        Context,
        {
            "model": model,
            "session": model.Session,
            "user": current_user.name,
            "schema": _db_to_form_schema(group_type=group_type),
            "for_view": True,
        },
    )
    data_dict: dict[str, Any] = {"id": id, "type": group_type}

    # unicode format (decoded from utf8)
    q = request.args.get("q", "")

    extra_vars["q"] = q

    limit = config.get("ckan.datasets_per_page")
    try:
        check_access_to_group(context, {"id": id})
    except NotAuthorized:
        base.abort(403, _("Unauthorized to read"))
    except NotFound:
        base.abort(
            404,
            (
                _("Group not found")
                if group_type == "group"
                else _("Organization not found")
            ),
        )
    try:
        # Do not query for the group datasets when dictizing, as they will
        # be ignored and get requested on the controller anyway
        data_dict["include_datasets"] = False
        data_dict["include_dataset_count"] = False

        # Do not query group members as they aren't used in the view
        data_dict["include_users"] = False

        group_show = _action("group_show")
        group_dict = group_show(context, data_dict)
    except NotFound:
        base.abort(404, _("Group not found"))
    except NotAuthorized:
        base.abort(403, _("Not authorized to see this page"))

    # if the user specified a group id, redirect to the group name
    if (
        data_dict["id"] == group_dict["id"]
        and data_dict["id"] != group_dict["name"]
    ):
        url_with_name = h.url_for(
            "{}.read".format(group_type), id=group_dict["name"]
        )

        return h.redirect_to(h.add_url_param(alternative_url=url_with_name))

    # TODO: Remove
    # ckan 2.9: Adding variables that were removed from c object for
    # compatibility with templates in existing extensions
    g.q = q
    g.group_dict = group_dict

    extra_vars = _read(id, limit, group_type)

    extra_vars["group_type"] = group_type
    extra_vars["group_dict"] = group_dict
    return base.render(
        _get_group_template("read_template", cast(str, g.group_dict["type"])),
        extra_vars,
    )


def about(id: str, group_type: str, is_organization: bool) -> str:
    extra_vars = {}
    set_org(is_organization)
    context = cast(
        Context,
        {"model": model, "session": model.Session, "user": current_user.name},
    )
    try:
        check_access_to_group(context, {"id": id})
    except NotAuthorized:
        base.abort(403, _("Unauthorized to read"))
    except NotFound:
        base.abort(404, _("Not found"))

    group_dict = _get_group_dict(id, group_type)
    group_type = group_dict["type"]
    _setup_template_variables(context, {"id": id}, group_type=group_type)

    # TODO: Remove
    # ckan 2.9: Adding variables that were removed from c object for
    # compatibility with templates in existing extensions
    g.group_dict = group_dict
    g.group_type = group_type

    extra_vars: dict[str, Any] = {
        "group_dict": group_dict,
        "group_type": group_type,
    }

    return base.render(
        _get_group_template("about_template", group_type), extra_vars
    )


def members(id: str, group_type: str, is_organization: bool) -> str:
    set_org(is_organization)
    context = cast(
        Context,
        {"model": model, "session": model.Session, "user": current_user.name},
    )

    try:
        check_access_to_group(context, {"id": id})
        data_dict: dict[str, Any] = {"id": id}
        assert check_access("group_edit_permissions", context, data_dict)
        member_list = get_action("member_list")
        members = member_list(context, {"id": id, "object_type": "user"})
        data_dict["include_datasets"] = False
        group_show = _action("group_show")
        group_dict = group_show(context, data_dict)
    except NotFound:
        base.abort(404, _("Group not found"))
    except NotAuthorized:
        base.abort(
            403,
            _("User %r not authorized to edit members of %s")
            % (current_user.name, id),
        )

    # TODO: Remove
    # ckan 2.9: Adding variables that were removed from c object for
    # compatibility with templates in existing extensions
    g.members = members
    g.group_dict = group_dict

    extra_vars: dict[str, Any] = {
        "members_count": len(members),
        "members": members,
        "group_dict": group_dict,
        "group_type": group_type,
    }
    return base.render(_replace_group_org("group/members.html"), extra_vars)


def member_delete(
    id: str, group_type: str, is_organization: bool
) -> Union[Response, str]:
    extra_vars = {}
    set_org(is_organization)
    if "cancel" in request.form:
        return h.redirect_to("{}.members".format(group_type), id=id)

    context = cast(
        Context,
        {"model": model, "session": model.Session, "user": current_user.name},
    )
    try:
        assert _check_access("group_member_delete", context, {"id": id})
    except NotAuthorized:
        base.abort(403, _("Unauthorized to delete group %s members") % "")

    try:
        user_id = request.args.get("user")
        if not user_id:
            base.abort(404, _("User not found"))
        if request.method == "POST":
            _log_group_member_delete(
                group_type, id, user_id, context.get("user")
            )
            _action("group_member_delete")(
                context, {"id": id, "user_id": user_id}
            )
            message = (
                _("Group member has been deleted")
                if group_type == "group"
                else _("Organization member has been deleted")
            )
            h.flash_notice(message)
            return h.redirect_to("{}.members".format(group_type), id=id)
        user_show = _action("user_show")
        user_dict = user_show(context, {"id": user_id})

    except NotAuthorized:
        base.abort(403, _("Unauthorized to delete group %s members") % "")
    except NotFound:
        base.abort(404, _("Group not found"))
    extra_vars: dict[str, Any] = {
        "user_id": user_id,
        "user_dict": user_dict,
        "group_id": id,
        "group_type": group_type,
    }
    return base.render(
        _replace_group_org("group/confirm_delete_member.html"), extra_vars
    )


def _log_group_member_delete(
    group_type: str, group_id: str, user_id: str, user_initiator_name: str
):
    username = None
    role = None

    try:
        group_dict = _get_group_dict(group_id, group_type)
        user = next(u for u in group_dict["users"] if u["id"] == user_id)
        if user:
            username = user["name"]
            role = user["capacity"]
        log.info(
            f"group_member_delete: "
            f"username = {username}, "
            f"role = {_(role.title())}, "
            f"group_id = {group_id}, "
            f'group_type = {_("{}".format(group_type))}, '
            f'group_name = {group_dict.get("name")}, '
            f"user_initiator_name = {user_initiator_name}"
        )
    except Exception as e:
        log.error("group_member_delete error: %r", e.args)


def follow(id: str, group_type: str, is_organization: bool) -> Response:
    """Start following this group."""
    set_org(is_organization)
    context = cast(
        Context,
        {"model": model, "session": model.Session, "user": current_user.name},
    )
    data_dict = {"id": id}
    try:
        follow_group = get_action("follow_group")
        follow_group(context, data_dict)
        group_show = get_action("group_show")
        group_dict = group_show(context, data_dict)
        h.flash_success(
            _("You are now following {0}").format(group_dict["title"])
        )

        id = group_dict["name"]
    except ValidationError as e:
        error_message = e.message or e.error_summary or e.error_dict
        h.flash_error(error_message)
    except NotAuthorized as e:
        h.flash_error(e.message)
    return h.redirect_to("group.read", id=id)


def unfollow(id: str, group_type: str, is_organization: bool) -> Response:
    """Stop following this group."""
    set_org(is_organization)
    context = cast(
        Context,
        {"model": model, "session": model.Session, "user": current_user.name},
    )
    data_dict = {"id": id}
    try:
        unfollow_group = get_action("unfollow_group")
        unfollow_group(context, data_dict)
        group_show = get_action("group_show")
        group_dict = group_show(context, data_dict)
        h.flash_success(
            _("You are no longer following {0}").format(group_dict["title"])
        )
        id = group_dict["name"]
    except ValidationError as e:
        error_message = e.message or e.error_summary or e.error_dict
        h.flash_error(error_message)
    except NotFound as e:
        error_message = e.message or ""
        base.abort(404, _(error_message))
    except NotAuthorized as e:
        error_message = e.message or ""
        base.abort(403, _(error_message))
    return h.redirect_to("group.read", id=id)


def followers(id: str, group_type: str, is_organization: bool) -> str:
    set_org(is_organization)
    context = cast(
        Context,
        {"model": model, "session": model.Session, "user": current_user.name},
    )
    group_dict = _get_group_dict(id, group_type)
    try:
        group_follower_list = get_action("group_follower_list")
        followers = group_follower_list(context, {"id": id})
    except NotAuthorized:
        base.abort(403, _("Unauthorized to view followers %s") % "")

    # TODO: Remove
    # ckan 2.9: Adding variables that were removed from c object for
    # compatibility with templates in existing extensions
    g.group_dict = group_dict
    g.followers = followers

    extra_vars: dict[str, Any] = {
        "group_dict": group_dict,
        "group_type": group_type,
        "followers": followers,
    }
    return base.render("group/followers.html", extra_vars)


def admins(id: str, group_type: str, is_organization: bool) -> str:
    extra_vars = {}
    set_org(is_organization)
    group_dict = _get_group_dict(id, group_type)
    admins = authz.get_group_or_org_admin_ids(id)

    # TODO: Remove
    # ckan 2.9: Adding variables that were removed from c object for
    # compatibility with templates in existing extensions
    g.group_dict = group_dict
    g.admins = admins

    extra_vars: dict[str, Any] = {
        "group_dict": group_dict,
        "group_type": group_type,
        "admins": admins,
    }

    return base.render(
        _get_group_template("admins_template", group_dict["type"]), extra_vars
    )


class BulkProcessView(MethodView):
    """Bulk process view"""

    def _prepare(self, group_type: str, id: str) -> Context:

        # check we are org admin

        context = cast(
            Context,
            {
                "model": model,
                "session": model.Session,
                "user": current_user.name,
                "schema": _db_to_form_schema(group_type=group_type),
                "for_view": True,
                "extras_as_string": True,
            },
        )

        try:
            check_access_to_group(context, {"id": id})
        except NotAuthorized:
            base.abort(403, _("Unauthorized to read"))
        except NotFound:
            base.abort(404, _("Not found"))

        try:
            check_access("bulk_update_public", context, {"org_id": id})
        except NotAuthorized:
            base.abort(403, _("Unauthorized to access"))

        return context

    def get(self, id: str, group_type: str, is_organization: bool) -> str:
        set_org(is_organization)
        context = self._prepare(group_type, id)
        data_dict: dict[str, Any] = {"id": id, "type": group_type}
        data_dict["include_datasets"] = False
        try:
            group_show = _action("group_show")
            group_dict = group_show(context, data_dict)
            group = context["group"]
        except NotFound:
            base.abort(404, _("Group not found"))

        if not group_dict["is_organization"]:
            # FIXME: better error
            raise Exception("Must be an organization")

        # If no action then just show the datasets
        limit = 500
        # TODO: Remove
        # ckan 2.9: Adding variables that were removed from c object for
        # compatibility with templates in existing extensions
        g.group_dict = group_dict
        extra_vars = _read(id, limit, group_type)
        extra_vars["packages"] = g.page.items
        extra_vars["group_dict"] = group_dict
        extra_vars["group"] = group

        return base.render(
            _get_group_template("bulk_process_template", group_type),
            extra_vars,
        )

    def post(
        self, id: str, group_type: str, is_organization: bool
    ) -> Response:
        set_org(is_organization)
        context = self._prepare(group_type, id)
        data_dict: dict[str, Any] = {"id": id, "type": group_type}
        user = current_user.name
        try:
            # Do not query for the group datasets when dictizing, as they will
            # be ignored and get requested on the controller anyway
            data_dict["include_datasets"] = False
            group_show = _action("group_show")
            group_dict = group_show(context, data_dict)
        except NotFound:
            default_label = _("Organization" if is_organization else "Group")
            group_label = (
                h.humanize_entity_type(
                    "organization" if is_organization else "group",
                    group_type,
                    "default label",
                )
                or default_label
            )
            base.abort(404, _("{} not found".format(group_label)))
        except NotAuthorized:
            base.abort(
                403, _("User %r not authorized to edit %s") % (user, id)
            )

        if not group_dict["is_organization"]:
            # FIXME: better error
            raise Exception("Must be an organization")

        # TODO: Remove
        # ckan 2.9: Adding variables that were removed from c object for
        # compatibility with templates in existing extensions
        g.group_dict = group_dict

        # use different form names so that ie7 can be detected
        form_names = {
            "bulk_action.public",
            "bulk_action.delete",
            "bulk_action.private",
        }
        actions_in_form: set[str] = set(request.form.keys())
        actions = form_names.intersection(actions_in_form)
        # ie7 puts all buttons in form params but puts submitted one twice

        form_dict: dict[str, str] = request.form.to_dict()
        for key, value in form_dict.items():
            if value in ["private", "public"]:
                action = key.split(".")[-1]
                break
        else:
            # normal good browser form submission
            action = actions.pop().split(".")[-1]

        # process the action first find the datasets to perform the action on.
        # they are prefixed by dataset_ in the form data
        datasets = []
        for param in request.form:
            if param.startswith("dataset_"):
                datasets.append(param[8:])

        action_functions = {
            "private": "bulk_update_private",
            "public": "bulk_update_public",
            "delete": "bulk_update_delete",
        }

        data_dict = {"datasets": datasets, "org_id": group_dict["id"]}

        try:
            get_action(action_functions[action])(context, data_dict)
        except NotAuthorized:
            base.abort(403, _("Not authorized to perform bulk update"))
        return h.redirect_to("{}.bulk_process".format(group_type), id=id)


class CreateGroupView(MethodView):
    """Create group view"""

    def _prepare(self, data: Optional[dict[str, Any]] = None) -> Context:
        if data and "type" in data:
            group_type = data["type"]
        else:
            group_type = _guess_group_type()
        if data:
            data["type"] = group_type

        context = cast(
            Context,
            {
                "model": model,
                "session": model.Session,
                "user": current_user.name,
                "save": "save" in request.args,
                "parent": request.args.get("parent", None),
                "group_type": group_type,
            },
        )

        try:
            assert _check_access("group_create", context)
        except NotAuthorized:
            base.abort(403, _("Unauthorized to create a group"))

        return context

    def post(
        self, group_type: str, is_organization: bool
    ) -> Union[Response, str]:
        set_org(is_organization)
        context = self._prepare()
        try:
            data_dict = clean_dict(
                dict_fns.unflatten(tuplize_dict(parse_params(request.form)))
            )
            data_dict.update(
                clean_dict(
                    dict_fns.unflatten(
                        tuplize_dict(parse_params(request.files))
                    )
                )
            )
        except dict_fns.DataError:
            base.abort(400, _("Integrity Error"))
        user = current_user.name
        data_dict["type"] = group_type or "group"
        data_dict["users"] = [{"name": user, "capacity": "admin"}]
        try:
            group_create = _action("group_create")
            group = group_create(context, data_dict)
        except NotFound:
            base.abort(404, _("Group not found"))
        except NotAuthorized:
            base.abort(403, _("Not authorized to see this page"))
        except ValidationError as e:
            errors = e.error_dict
            error_summary = e.error_summary
            return self.get(
                group_type, is_organization, data_dict, errors, error_summary
            )
        return h.redirect_to(
            cast(str, group["type"]) + ".read", id=group["name"]
        )

    def get(
        self,
        group_type: str,
        is_organization: bool,
        data: Optional[dict[str, Any]] = None,
        errors: Optional[dict[str, Any]] = None,
        error_summary: Optional[dict[str, Any]] = None,
    ) -> str:
        set_org(is_organization)
        context = self._prepare()
        data = data or clean_dict(
            dict_fns.unflatten(
                tuplize_dict(
                    parse_params(request.args, ignore_keys=CACHE_PARAMETERS)
                )
            )
        )

        if not data.get("image_url", "").startswith("http"):
            data.pop("image_url", None)
        errors = errors or {}
        error_summary = error_summary or {}
        extra_vars: dict[str, Any] = {
            "data": data,
            "errors": errors,
            "error_summary": error_summary,
            "action": "new",
            "group_type": group_type,
        }
        _setup_template_variables(context, data, group_type=group_type)
        form = base.render(
            _get_group_template("group_form", group_type), extra_vars
        )

        # TODO: Remove
        # ckan 2.9: Adding variables that were removed from c object for
        # compatibility with templates in existing extensions
        g.form = form

        extra_vars["form"] = form
        return base.render(
            _get_group_template("new_template", group_type), extra_vars
        )


class EditGroupView(MethodView):
    """Edit group view"""

    def _prepare(self, id: Optional[str]) -> Context:
        data_dict: dict[str, Any] = {"id": id, "include_datasets": False}

        context = cast(
            Context,
            {
                "model": model,
                "session": model.Session,
                "user": current_user.name,
                "save": "save" in request.args,
                "for_edit": True,
                "parent": request.args.get("parent", None),
                "id": id,
            },
        )

        try:
            group_show = _action("group_show")
            group_show(context, data_dict)
            _check_access("group_update", context, {"id": id})
        except NotAuthorized:
            base.abort(403, _("Unauthorized to create a organization"))
        except NotFound:
            base.abort(404, _("Organization not found"))

        return context

    def post(
        self, group_type: str, is_organization: bool, id: Optional[str] = None
    ) -> Union[Response, str]:
        set_org(is_organization)
        context = self._prepare(id)
        try:
            check_access_to_group(context, {"id": id})
        except NotAuthorized:
            base.abort(403, _("Unauthorized to read"))
        except NotFound:
            base.abort(404, _("Organization not found"))

        try:
            data_dict = clean_dict(
                dict_fns.unflatten(tuplize_dict(parse_params(request.form)))
            )
            data_dict.update(
                clean_dict(
                    dict_fns.unflatten(
                        tuplize_dict(parse_params(request.files))
                    )
                )
            )
        except dict_fns.DataError:
            base.abort(400, _("Integrity Error"))
        data_dict["id"] = context["id"]
        context["allow_partial_update"] = True
        try:
            group_update = _action("group_update")
            group = group_update(context, data_dict)
        except NotFound:
            base.abort(404, _("Organization not found"))
        except NotAuthorized:
            base.abort(403, _("Not authorized to see this page"))
        except ValidationError as e:
            errors = e.error_dict
            error_summary = e.error_summary
            assert id
            return self.get(
                id,
                group_type,
                is_organization,
                data_dict,
                errors,
                error_summary,
            )
        return h.redirect_to(
            cast(str, group["type"]) + ".read", id=group["name"]
        )

    def get(
        self,
        id: str,
        group_type: str,
        is_organization: bool,
        data: Optional[dict[str, Any]] = None,
        errors: Optional[dict[str, Any]] = None,
        error_summary: Optional[dict[str, Any]] = None,
    ) -> str:
        set_org(is_organization)
        context = self._prepare(id)
        data_dict: dict[str, Any] = {"id": id, "include_datasets": False}
        try:
            check_access_to_group(context, {"id": id})
            group_show = _action("group_show")
            group_dict = group_show(context, data_dict)
        except NotFound:
            base.abort(404, _("Group not found"))
        except NotAuthorized:
            base.abort(403, _("Not authorized to see this page"))
        data = data or group_dict
        assert data is not None
        errors = errors or {}
        extra_vars: dict[str, Any] = {
            "data": data,
            "group_dict": group_dict,
            "errors": errors,
            "error_summary": error_summary,
            "action": "edit",
            "group_type": group_type,
        }

        _setup_template_variables(context, data, group_type=group_type)
        form = base.render(
            _get_group_template("group_form", group_type), extra_vars
        )

        # TODO: Remove
        # ckan 2.9: Adding variables that were removed from c object for
        # compatibility with templates in existing extensions
        g.grouptitle = group_dict.get("title")
        g.groupname = group_dict.get("name")
        g.data = data
        g.group_dict = group_dict

        extra_vars["form"] = form
        template = _get_group_template("edit_template", group_type)
        return base.render(template, extra_vars)


class DeleteGroupView(MethodView):
    """Delete group view"""

    def _prepare(self, id: Optional[str] = None) -> Context:
        context = cast(
            Context,
            {
                "model": model,
                "session": model.Session,
                "user": current_user.name,
            },
        )
        try:
            check_access_to_group(context, {"id": id})
            assert _check_access("group_delete", context, {"id": id})
        except (NotAuthorized, NotFound):
            base.abort(403, _("Unauthorized to delete group %s") % id)
        return context

    def post(
        self, group_type: str, is_organization: bool, id: Optional[str] = None
    ) -> Response:
        set_org(is_organization)
        context = self._prepare(id)
        try:
            group_delete = _action("group_delete")
            group_delete(context, {"id": id})
            group_label = (
                _("Group has been deleted")
                if group_type == "group"
                else _("Organization has been deleted")
            )
            h.flash_notice(_("%s has been deleted.") % _(group_label))
        except NotAuthorized:
            base.abort(403, _("Unauthorized to delete group %s") % id)
        except NotFound:
            base.abort(404, _("Group not found"))
        except ValidationError as e:
            base.abort(403, _(e.error_dict["message"]))

        return h.redirect_to("{}.index".format(group_type))

    def get(
        self, group_type: str, is_organization: bool, id: Optional[str] = None
    ) -> Union[str, Response]:
        set_org(is_organization)
        context = self._prepare(id)
        group_show = _action("group_show")
        group_dict = group_show(context, {"id": id})
        if "cancel" in request.args:
            return h.redirect_to("{}.edit".format(group_type), id=id)

        # TODO: Remove
        g.group_dict = group_dict
        extra_vars: dict[str, Any] = {
            "group_dict": group_dict,
            "group_type": group_type,
        }
        return base.render(
            _replace_group_org("group/confirm_delete.html"), extra_vars
        )


class MembersGroupView(MethodView):
    """New members group view"""

    def _prepare(self, id: Optional[str] = None) -> Context:
        context = cast(
            Context,
            {
                "model": model,
                "session": model.Session,
                "user": current_user.name,
            },
        )
        try:
            assert _check_access("group_member_create", context, {"id": id})
        except NotAuthorized:
            base.abort(403, _("Unauthorized to create group %s members") % "")
        return context

    def post(
        self, group_type: str, is_organization: bool, id: Optional[str] = None
    ) -> Response:
        set_org(is_organization)
        context = self._prepare(id)
        data_dict = clean_dict(
            dict_fns.unflatten(tuplize_dict(parse_params(request.form)))
        )
        try:
            check_access_to_group(context, {"id": id})
        except NotAuthorized:
            base.abort(403, _("Unauthorized to read"))
        except NotFound:
            base.abort(404, _("Not found"))

        data_dict["id"] = id

        email = data_dict.get("email")

        if email:
            user_data_dict: dict[str, Any] = {
                "email": email,
                "group_id": data_dict["id"],
                "role": data_dict["role"],
            }
            del data_dict["email"]

            try:
                user_invite = _action("user_invite")
                user_dict = user_invite(context, user_data_dict)
            except ValidationError as e:
                for error in e.error_summary.values():
                    h.flash_error(error)
                return h.redirect_to("{}.member_new".format(group_type), id=id)

            data_dict["username"] = user_dict["name"]

        try:
            group_member_create = _action("group_member_create")
            group_dict = group_member_create(context, data_dict)
            self._log_group_member_create(group_type, data_dict, id)
        except NotAuthorized:
            base.abort(403, _("Unauthorized to add member to group %s") % id)
        except NotFound:
            base.abort(404, _("Group not found"))
        except ValidationError as e:
            for error in e.error_summary.values():
                h.flash_error(error)
            return h.redirect_to("{}.member_new".format(group_type), id=id)

        # TODO: Remove
        g.group_dict = group_dict

        return h.redirect_to("{}.members".format(group_type), id=id)

    def _log_group_member_create(
        self, group_type: str, data_dict, group_id: Optional[str] = None
    ):
        try:
            if group_id:
                group_dict = _get_group_dict(group_id, group_type)
                log.info(
                    f'group_member_create: username = {data_dict.get("username")}, '
                    f'role = {_(data_dict.get("role").title())}, '
                    f"group_id = {group_id}, "
                    f'group_type = {_("{}".format(group_type))}, '
                    f'group_name = {group_dict.get("name")}'
                )
            else:
                log.info(
                    f'group_member_create: username = {data_dict.get("username")}, '
                    f'role = {_(data_dict.get("role").title())}, '
                    f'group_type = {_("{}".format(group_type))}'
                )
        except Exception as e:
            log.error("group_member_create error: %r", e.args)

    def get(
        self, group_type: str, is_organization: bool, id: Optional[str] = None
    ) -> str:
        extra_vars: dict[str, Any] = {}
        set_org(is_organization)
        context = self._prepare(id)
        user = request.args.get("user")
        data_dict: dict[str, Any] = {"id": id}
        data_dict["include_datasets"] = False
        try:
            check_access_to_group(context, {"id": id})
        except NotAuthorized:
            base.abort(403, _("Unauthorized to read"))
        except NotFound:
            base.abort(404, _("Not found"))
        group_show = _action("group_show")
        group_dict = group_show(context, data_dict)
        member_roles_list = _action("member_roles_list")
        roles = member_roles_list(context, {"group_type": group_type})
        user_dict = {}
        if user:
            user_show = get_action("user_show")
            user_dict = user_show(context, {"id": user})
            user_role = authz.users_role_for_group_or_org(id, user) or "member"
            # TODO: Remove
            g.user_dict = user_dict
            extra_vars["user_dict"] = user_dict
        else:
            user_role = "member"

        # TODO: Remove
        g.group_dict = group_dict
        g.roles = roles
        g.user_role = user_role

        extra_vars.update(
            {
                "group_dict": group_dict,
                "roles": roles,
                "user_role": user_role,
                "group_type": group_type,
                "user_dict": user_dict,
            }
        )
        return base.render(
            _replace_group_org("group/member_new.html"), extra_vars
        )


group = Blueprint(
    "group",
    __name__,
    url_prefix="/group",
    url_defaults={"group_type": "group", "is_organization": False},
)
organization = Blueprint(
    "organization",
    __name__,
    url_prefix="/organization",
    url_defaults={"group_type": "organization", "is_organization": True},
)


@group.before_request
def before_request() -> None:
    session.pop("_flashes", None)
    if not current_user or current_user.is_anonymous:
        h.flash_error(_("Not authorized to see this page"))
        return h.redirect_to("user.login")  # type: ignore
    try:
        check_token = get_action("oidc_check_token")
        check_token({}, {})
    except NotAuthorized:
        session.delete()
        return h.redirect_to("user.login")  # type: ignore


@organization.before_request
def before_request() -> None:
    session.pop("_flashes", None)
    if not current_user or current_user.is_anonymous:
        h.flash_error(_("Not authorized to see this page"))
        return h.redirect_to("user.login")  # type: ignore
    try:
        check_token = get_action("oidc_check_token")
        if check_token:
            check_token({}, {})
    except NotAuthorized:
        session.delete()
        return h.redirect_to("user.login")  # type: ignore


def register_group_plugin_rules(blueprint: Blueprint) -> None:
    actions = ["member_delete", "followers", "follow", "unfollow", "admins"]
    blueprint.add_url_rule("/", view_func=index, strict_slashes=False)
    blueprint.add_url_rule(
        "/new",
        methods=["GET", "POST"],
        view_func=CreateGroupView.as_view("new"),
    )
    blueprint.add_url_rule("/<id>", methods=["GET"], view_func=read)
    blueprint.add_url_rule(
        "/edit/<id>", view_func=EditGroupView.as_view("edit")
    )
    blueprint.add_url_rule("/about/<id>", methods=["GET"], view_func=about)
    blueprint.add_url_rule(
        "/members/<id>", methods=["GET", "POST"], view_func=members
    )
    blueprint.add_url_rule(
        "/member_new/<id>", view_func=MembersGroupView.as_view("member_new")
    )
    blueprint.add_url_rule(
        "/bulk_process/<id>", view_func=BulkProcessView.as_view("bulk_process")
    )
    blueprint.add_url_rule(
        "/delete/<id>",
        methods=["GET", "POST"],
        view_func=DeleteGroupView.as_view("delete"),
    )
    for action in actions:
        blueprint.add_url_rule(
            "/{0}/<id>".format(action),
            methods=["GET", "POST"],
            view_func=globals()[action],
        )


register_group_plugin_rules(group)
register_group_plugin_rules(organization)
