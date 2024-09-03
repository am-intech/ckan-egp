# encoding: utf-8
from __future__ import annotations

import logging
from typing import Any, Optional, Union, cast

from flask import Blueprint
from flask.views import MethodView
from ckan.common import asbool
from six import ensure_str
import dominate.tags as dom_tags

import ckan.lib.authenticator as authenticator
import ckan.lib.base as base
import ckan.lib.captcha as captcha
from ckan.lib.helpers import helper_functions as h
from ckan.lib.helpers import Page
import ckan.lib.mailer as mailer
import ckan.lib.maintain as maintain
import ckan.lib.navl.dictization_functions as dictization_functions
from ckan.logic import get_action, NotFound, NotAuthorized, check_access, clean_dict, tuplize_dict, parse_params, \
    ValidationError
import ckan.logic.schema as schema
import ckan.model as model
import ckan.plugins as plugins
from ckan import authz
from ckan.common import (
    _, config, g, request, current_user, login_user, logout_user, session,
    repr_untrusted
)
from ckan.types import Context, Schema, Response
from ckan.lib import signals

log = logging.getLogger(__name__)

# hooks for subclasses
new_user_form = 'user/new_user_form.html'
edit_user_form = 'user/edit_user_form.html'

user = Blueprint('user', __name__, url_prefix='/user')


@maintain.deprecated('''set_repoze_user() is deprecated and will be removed.
                        Use login_user() instead''', since="2.10.0")
def set_repoze_user(user_id: str, resp: Optional[Response] = None) -> None:
    """
    This function is deprecated and will be removed.
    It exists only to maintain backward compatibility
    to extensions like saml2auth.
    """
    user_obj = model.User.get(user_id)
    login_user(user_obj)


def _edit_form_to_db_schema() -> Schema:
    return schema.user_edit_form_schema()


def _new_form_to_db_schema() -> Schema:
    return schema.user_new_form_schema()


def _extra_template_variables(context: Context,
                              data_dict: dict[str, Any]) -> dict[str, Any]:
    is_sysadmin = False
    if current_user.is_authenticated:
        is_sysadmin = authz.is_sysadmin(current_user.name)
    try:
        user_show = get_action('user_show')
        user_dict = user_show(context, data_dict)
    except NotFound:
        base.abort(404, _('User not found'))
    except NotAuthorized:
        base.abort(403, _('Not authorized to see this page'))

    is_myself = user_dict['name'] == current_user.name
    about_formatted = h.render_markdown(user_dict['about'])
    extra: dict[str, Any] = {
        'is_sysadmin': is_sysadmin,
        'user_dict': user_dict,
        'is_myself': is_myself,
        'about_formatted': about_formatted
    }
    return extra


@user.before_request
def before_request() -> None:
    session.pop('_flashes', None)
    try:
        if not current_user or current_user.is_anonymous:
            raise NotAuthorized()
        context = cast(Context, {
            "model": model,
            "user": current_user.name,
            "auth_user_obj": current_user
        })
        check_access('site_read', context)
    except NotAuthorized:
        action = plugins.toolkit.get_endpoint()[1]
        if action not in ('login', 'request_reset', 'perform_reset'):
            base.abort(403, _('Not authorized to see this page'))
    try:
        check_token = get_action("oidc_check_token")
        if check_token:
            check_token({}, {})
    except NotAuthorized:
        session.delete()
        return h.redirect_to("user.login")  # type: ignore


def index():
    page_number = h.get_page_number(request.args)
    q = request.args.get('q', '')
    order_by = request.args.get('order_by', 'name')
    default_limit: int = config.get('ckan.user_list_limit')
    limit = int(request.args.get('limit', default_limit))
    context = cast(Context, {
        'return_query': True,
        'user': current_user.name,
        'auth_user_obj': current_user
    })

    data_dict = {
        'q': q,
        'order_by': order_by
    }

    try:
        check_access('user_list', context, data_dict)
    except NotAuthorized:
        base.abort(403, _('Not authorized to see this page'))

    user_list = get_action('user_list')
    users_list = user_list(context, data_dict)

    page = Page(
        collection=users_list,
        page=page_number,
        url=h.pager_url,
        item_count=users_list.count(),
        items_per_page=limit)

    extra_vars: dict[str, Any] = {
        'page': page,
        'q': q,
        'order_by': order_by
    }
    return base.render('user/list.html', extra_vars)


def me() -> Response:
    return h.redirect_to(
        config.get('ckan.auth.route_after_login'))


def read(id: str) -> Union[Response, str]:
    context = cast(Context, {
        'model': model,
        'session': model.Session,
        'user': current_user.name,
        'auth_user_obj': current_user,
        'for_view': True
    })
    data_dict: dict[str, Any] = {
        'id': id,
        'user_obj': current_user,
        'include_datasets': True,
        'include_num_followers': True
    }
    # FIXME: line 331 in multilingual plugins expects facets to be defined.
    # any ideas?
    g.fields = []

    extra_vars = _extra_template_variables(context, data_dict)
    if extra_vars is None:
        return h.redirect_to('user.login')
    return base.render('user/read.html', extra_vars)


class ApiTokenView(MethodView):
    def get(self,
            id: str,
            data: Optional[dict[str, Any]] = None,
            errors: Optional[dict[str, Any]] = None,
            error_summary: Optional[dict[str, Any]] = None
            ) -> Union[Response, str]:
        context = cast(Context, {
            'model': model,
            'session': model.Session,
            'user': current_user.name,
            'auth_user_obj': current_user,
            'for_view': True,
            'include_plugin_extras': True
        })
        try:
            api_token_list = get_action('api_token_list')
            tokens = api_token_list(context, {'user': id})
        except NotAuthorized:
            base.abort(403, _('Unauthorized to view API tokens.'))

        data_dict: dict[str, Any] = {
            'id': id,
            'user_obj': current_user,
            'include_datasets': True,
            'include_num_followers': True
        }

        extra_vars = _extra_template_variables(context, data_dict)
        if extra_vars is None:
            return h.redirect_to('user.login')
        extra_vars['tokens'] = tokens
        extra_vars.update({
            'data': data,
            'errors': errors,
            'error_summary': error_summary
        })
        return base.render('user/api_tokens.html', extra_vars)

    def post(self, id: str) -> Union[Response, str]:
        context = cast(Context, {'model': model})

        data_dict = clean_dict(dictization_functions.unflatten(tuplize_dict(parse_params(request.form))))

        data_dict['user'] = id
        try:
            api_token_create = get_action('api_token_create')
            token = api_token_create(context, data_dict)['token']
        except NotAuthorized:
            base.abort(403, _('Unauthorized to create API tokens.'))
        except ValidationError as e:
            errors = e.error_dict
            error_summary = e.error_summary
            return self.get(id, data_dict, errors, error_summary)

        copy_btn = dom_tags.button(dom_tags.i('', {
            'class': 'fa fa-copy'
        }), {
            'type': 'button',
            'class': 'btn btn-default btn-xs',
            'data-module': 'copy-into-buffer',
            'data-module-copy-value': ensure_str(token)
        })
        h.flash_success(
            _(
                "API Token created: <code style=\"word-break:break-all;\">"
                "{token}</code> {copy}<br>"
                "Make sure to copy it now, "
                "you won't be able to see it again!"
            ).format(token=ensure_str(token), copy=copy_btn),
            True
        )
        return h.redirect_to('user.api_tokens', id=id)


def api_token_revoke(id: str, jti: str) -> Response:
    context = cast(Context, {'model': model})
    try:
        api_token_revoke = get_action('api_token_revoke')
        api_token_revoke(context, {'jti': jti})
    except NotAuthorized:
        base.abort(403, _('Unauthorized to revoke API tokens.'))
    return h.redirect_to('user.api_tokens', id=id)

class RegisterView(MethodView):
    def _prepare(self):
        context = cast(Context, {
            'model': model,
            'session': model.Session,
            'user': current_user.name,
            'auth_user_obj': current_user,
            'schema': _new_form_to_db_schema(),
            'save': 'save' in request.form
        })
        try:
            check_access('user_create', context)
        except NotAuthorized:
            base.abort(403, _('Unauthorized to register as a user.'))
        return context

    def post(self) -> Union[Response, str]:
        context = self._prepare()
        try:
            data_dict = clean_dict(dictization_functions.unflatten(tuplize_dict(parse_params(request.form))))
            data_dict.update(clean_dict(dictization_functions.unflatten(tuplize_dict(parse_params(request.files)))))

        except dictization_functions.DataError:
            base.abort(400, _('Integrity Error'))

        try:
            captcha.check_recaptcha(request)
        except captcha.CaptchaError:
            error_msg = _('Bad Captcha. Please try again.')
            h.flash_error(error_msg)
            return self.get(data_dict)

        try:
            user_create = get_action('user_create')
            user_dict = user_create(context, data_dict)
        except NotAuthorized:
            base.abort(403, _('Unauthorized to create user %s') % '')
        except NotFound:
            base.abort(404, _('User not found'))
        except ValidationError as e:
            errors = e.error_dict
            error_summary = e.error_summary
            return self.get(data_dict, errors, error_summary)

        user = current_user.name
        if user:
            # #1799 User has managed to register whilst logged in - warn user
            # they are not re-logged in as new user.
            h.flash_success(
                _('User "%s" is now registered but you are still logged in as "%s" from before') % (data_dict[u'name'], user))
            if authz.is_sysadmin(user):
                # the sysadmin created a new user. We redirect him to the
                # activity page for the newly created user
                if "activity" in g.plugins:
                    return h.redirect_to('activity.user_activity', id=data_dict['name'])
                return h.redirect_to('user.read', id=data_dict['name'])
            else:
                return base.render('user/logout_first.html')

        # log the user in programatically
        userobj = model.User.get(user_dict["id"])
        if userobj:
            login_user(userobj)
            rotate_token()
        resp = h.redirect_to('user.me')
        return resp

    def get(self,
            data: Optional[dict[str, Any]] = None,
            errors: Optional[dict[str, Any]] = None,
            error_summary: Optional[dict[str, Any]] = None) -> str:
        self._prepare()
        user = current_user.name

        if user and not data and not authz.is_sysadmin(user):
            # #1799 Don't offer the registration form if already logged in
            return base.render('user/logout_first.html', {})

        form_vars = {
            'data': data or {},
            'errors': errors or {},
            'error_summary': error_summary or {}
        }

        extra_vars: dict[str, Any] = {
            'is_sysadmin': authz.is_sysadmin(user),
            'form': base.render(new_user_form, form_vars)
        }
        return base.render('user/new.html', extra_vars)


def next_page_or_default(target: Optional[str]) -> Response:
    if target and h.url_is_local(target):
        return h.redirect_to(target)
    return me()


def rotate_token():
    """
    Change the CSRF token - should be done on login
    for security purposes.
    """
    from flask_wtf.csrf import generate_csrf

    field_name = config.get("WTF_CSRF_FIELD_NAME")
    if session.get(field_name):
        session.pop(field_name)
        generate_csrf()


def login() -> Union[Response, str]:
    for item in plugins.PluginImplementations(plugins.IAuthenticator):
        response = item.login()
        if response:
            return response

    extra_vars: dict[str, Any] = {}

    if current_user.is_authenticated:
        return base.render("user/logout_first.html", extra_vars)

    if request.method == "POST":
        username_or_email = request.form.get("login")
        password = request.form.get("password")
        _remember = request.form.get("remember")

        identity = {
            "login": username_or_email,
            "password": password
        }

        user_obj = authenticator.ckan_authenticator(identity)
        if user_obj:
            next = request.args.get('next', request.args.get('came_from'))
            if _remember:
                from datetime import timedelta
                duration_time = timedelta(milliseconds=int(_remember))
                login_user(user_obj, remember=True, duration=duration_time)
                rotate_token()
                return next_page_or_default(next)
            else:
                login_user(user_obj)
                rotate_token()
                return next_page_or_default(next)
        else:
            err = _("Login failed. Bad username or password.")
            h.flash_error(err)
            return base.render("user/login.html", extra_vars)

    return base.render("user/login.html", extra_vars)


def logout() -> Response:
    for item in plugins.PluginImplementations(plugins.IAuthenticator):
        response = item.logout()
        if response:
            return response
    user = current_user.name
    if not user:
        return h.redirect_to('user.login')

    came_from = request.args.get('came_from', '')
    logout_user()

    field_name = config.get("WTF_CSRF_FIELD_NAME")
    if session.get(field_name):
        session.pop(field_name)

    if h.url_is_local(came_from):
        return h.redirect_to(str(came_from))

    return h.redirect_to('user.logged_out_page')


def logged_out_page() -> str:
    return base.render('user/logout.html', {})


def delete(id: str) -> Union[Response, Any]:
    '''Delete user with id passed as parameter'''
    context = cast(Context, {
        'model': model,
        'session': model.Session,
        'user': current_user.name,
        'auth_user_obj': current_user
    })
    data_dict = {'id': id}

    if 'cancel' in request.form:
        return h.redirect_to('user.edit', id=id)

    try:
        if request.method == 'POST':
            user_delete = get_action('user_delete')
            user_delete(context, data_dict)
        user_show = get_action('user_show')
        user_dict = user_show(context, {'id': id})
    except NotAuthorized:
        msg = _('Unauthorized to delete user with id "{user_id}".')
        return base.abort(403, msg.format(user_id=id))
    except NotFound as e:
        return base.abort(404, _(e.message))

    if request.method == 'POST' and current_user.is_authenticated:
        if current_user.id == id:  # type: ignore
            return logout()
        else:
            user_index = h.url_for('user.index')
            return h.redirect_to(user_index)

    # TODO: Remove
    # ckan 2.9: Adding variables that were removed from c object for
    # compatibility with templates in existing extensions
    g.user_dict = user_dict
    g.user_id = id

    extra_vars = {
        "user_id": id,
        "user_dict": user_dict
    }
    return base.render('user/confirm_delete.html', extra_vars)


class RequestResetView(MethodView):
    def _prepare(self):
        context = cast(Context, {
            'model': model,
            'session': model.Session,
            'user': current_user.name,
            'auth_user_obj': current_user
        })
        try:
            check_access('request_reset', context)
        except NotAuthorized:
            base.abort(403, _('Unauthorized to request reset password.'))

    def post(self) -> Response:
        self._prepare()
        id = request.form.get('user', '')
        if id in (None, ''):
            h.flash_error(_('Email is required'))
            return h.redirect_to('user.request_reset')
        log.info('Password reset requested for user %s', repr_untrusted(id))

        context = cast(
            Context, {
                'model': model,
                'user': current_user.name,
                'ignore_auth': True
            }
        )
        user_objs: list[model.User] = []

        # Usernames cannot contain '@' symbols
        user_show = get_action('user_show')
        if '@' in id:
            # Search by email address
            # (You can forget a user id, but you don't tend to forget your
            # email)
            user__list = get_action('user_list')
            user_list = user__list(context, {'email': id})
            if user_list:
                # send reset emails for *all* user accounts with this email
                # (otherwise we'd have to silently fail - we can't tell the
                # user, as that would reveal the existence of accounts with
                # this email address)
                for user_dict in user_list:
                    # This is ugly, but we need the user object for the mailer,
                    # and user_list does not return them
                    user_show(context, {'id': user_dict['id']})
                    user_objs.append(context['user_obj'])

        else:
            # Search by user name
            # (this is helpful as an option for a user who has multiple
            # accounts with the same email address and they want to be
            # specific)
            try:
                user_show(context, {'id': id})
                user_objs.append(context['user_obj'])
            except NotFound:
                pass

        if not user_objs:
            log.info('User requested reset link for unknown user: %s',repr_untrusted(id))
            log.info('User requested reset link for unknown user: {}'.format(id))

        for user_obj in user_objs:
            log.info('Emailing reset link to user: {}'.format(user_obj.name))
            try:
                # FIXME: How about passing user.id instead? Mailer already
                # uses model and it allow to simplify code above
                mailer.send_reset_link(user_obj)
                signals.request_password_reset.send(
                    user_obj.name, user=user_obj)
            except mailer.MailerException as e:
                # SMTP is not configured correctly or the server is
                # temporarily unavailable
                h.flash_error(_('Error sending the email. Try again later or contact an administrator for help'))
                log.exception(e)
                return h.redirect_to(config.get('ckan.user_reset_landing_page'))

        # always tell the user it succeeded, because otherwise we reveal
        # which accounts exist or not
        h.flash_success(
            _('A reset link has been emailed to you (unless the account specified does not exist)'))
        return h.redirect_to(config.get('ckan.user_reset_landing_page'))

    def get(self) -> str:
        self._prepare()
        return base.render('user/request_reset.html', {})


class PerformResetView(MethodView):
    def _prepare(self, id: str) -> tuple[Context, dict[str, Any]]:
        # FIXME 403 error for invalid key is a non helpful page
        context = cast(Context, {
            'model': model,
            'session': model.Session,
            'user': id,
            'keep_email': True
        })

        try:
            check_access('user_reset', context)
        except NotAuthorized:
            base.abort(403, _('Unauthorized to reset password.'))

        try:
            user_show = get_action('user_show')
            user_dict = user_show(context, {'id': id})
        except NotFound:
            base.abort(404, _('User not found'))
        user_obj = context['user_obj']
        g.reset_key = request.args.get('key')
        if not mailer.verify_reset_link(user_obj, g.reset_key):
            msg = _('Invalid reset key. Please try again.')
            h.flash_error(msg)
            base.abort(403, msg)
        return context, user_dict

    def _get_form_password(self):
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        if (password1 is not None and password1 != ''):
            if len(password1) < 8:
                raise ValueError(_('Your password must be 8 characters or longer.'))
            elif password1 != password2:
                raise ValueError(_('The passwords you entered do not match.'))
            return password1
        msg = _('You must provide a password')
        raise ValueError(msg)

    def post(self, id: str) -> Union[Response, str]:
        context, user_dict = self._prepare(id)
        context['reset_password'] = True
        user_state = user_dict['state']
        try:
            new_password = self._get_form_password()
            user_dict['password'] = new_password
            username = request.form.get('name')
            if username:
                user_dict['name'] = username
            user_dict['reset_key'] = g.reset_key
            user_update = get_action("user_update")
            updated_user = user_update(context, user_dict)
            # Users can not change their own state, so we need another edit
            if updated_user["state"] == model.State.PENDING:
                get_site_user = get_action("get_site_user")
                site_user = get_site_user({"ignore_auth": True}, {})
                patch_context = cast(Context, {'user': site_user["name"]})
                user_patch = get_action("user_patch")
                user_patch(patch_context, {"id": user_dict['id'], "state": model.State.ACTIVE})
            mailer.create_reset_key(context['user_obj'])
            signals.perform_password_reset.send(username, user=context['user_obj'])

            h.flash_success(_('Your password has been reset.'))
            return h.redirect_to(config.get('ckan.user_reset_landing_page'))

        except NotAuthorized:
            h.flash_error(_('Unauthorized to edit user %s') % id)
        except NotFound:
            h.flash_error(_('User not found'))
        except dictization_functions.DataError:
            h.flash_error(_('Integrity Error'))
        except ValidationError as e:
            h.flash_error('%r' % e.error_dict)
        except ValueError as e:
            h.flash_error(str(e))
        user_dict['state'] = user_state
        return base.render('user/perform_reset.html', {'user_dict': user_dict})

    def get(self, id: str) -> str:
        user_dict = self._prepare(id)[1]
        return base.render('user/perform_reset.html', {'user_dict': user_dict})


def follow(id: str) -> Response:
    '''Start following this user.'''
    context = cast(Context, {
        'model': model,
        'session': model.Session,
        'user': current_user.name,
        'auth_user_obj': current_user
    })
    data_dict: dict[str, Any] = {'id': id, 'include_num_followers': True}
    try:
        follow_user = get_action('follow_user')
        follow_user(context, data_dict)
        user_show = get_action('user_show')
        user_dict = user_show(context, data_dict)
        h.flash_success(_('You are now following {0}').format(user_dict['display_name']))
    except ValidationError as e:
        error_message: Any = (e.message or e.error_summary or e.error_dict)
        h.flash_error(error_message)
    except (NotFound, NotAuthorized) as e:
        h.flash_error(e.message)
    return h.redirect_to('user.read', id=id)


def unfollow(id: str) -> Response:
    '''Stop following this user.'''
    context = cast(Context, {
        'model': model,
        'session': model.Session,
        'user': current_user.name,
        'auth_user_obj': current_user
    })
    data_dict: dict[str, Any] = {'id': id, 'include_num_followers': True}
    try:
        unfollow_user = get_action('unfollow_user')
        unfollow_user(context, data_dict)
        user_show = get_action('user_show')
        user_dict = user_show(context, data_dict)
        h.flash_success(_('You are no longer following {0}').format(user_dict['display_name']))
    except ValidationError as e:
        error_message: Any = (e.error_summary or e.message or e.error_dict)
        h.flash_error(error_message)
    except (NotFound, NotAuthorized) as e:
        h.flash_error(e.message)
    return h.redirect_to('user.read', id=id)


def followers(id: str) -> str:
    context = cast(Context, {
        'for_view': True,
        'user': current_user.name,
        'auth_user_obj': current_user
    })
    data_dict: dict[str, Any] = {
        'id': id,
        'user_obj': current_user,
        'include_num_followers': True
    }
    extra_vars = _extra_template_variables(context, data_dict)
    user_follower_list = get_action('user_follower_list')
    try:
        extra_vars['followers'] = user_follower_list(context, {'id': extra_vars['user_dict']['id']})
    except NotAuthorized:
        base.abort(403, _('Unauthorized to view followers %s') % '')
    return base.render('user/followers.html', extra_vars)


def sysadmin() -> Response:
    username = request.form.get('username')
    status = asbool(request.form.get('status'))

    try:
        context = cast(Context, {
            'model': model,
            'session': model.Session,
            'user': current_user.name,
            'auth_user_obj': current_user,
        })
        data_dict: dict[str, Any] = {'id': username, 'sysadmin': status}
        user_patch = get_action('user_patch')
        user = user_patch(context, data_dict)
    except NotAuthorized:
        return base.abort(403, _('Not authorized to promote user to sysadmin'))
    except NotFound:
        return base.abort(404, _('User not found'))

    if status:
        h.flash_success(_('Promoted {} to sysadmin'.format(user['display_name'])))
    else:
        h.flash_success(_('Revoked sysadmin permission from {}'.format(user['display_name'])))
    return h.redirect_to('admin.index')


user.add_url_rule('/', view_func=index, strict_slashes=False)
user.add_url_rule('/me', view_func=me)
user.add_url_rule('/register', view_func=RegisterView.as_view('register'))
user.add_url_rule('/login', view_func=login, methods=('GET', 'POST'))
user.add_url_rule('/_logout', view_func=logout)
user.add_url_rule('/logged_out_redirect', view_func=logged_out_page)
user.add_url_rule('/delete/<id>', view_func=delete, methods=('POST', 'GET'))
user.add_url_rule('/reset', view_func=RequestResetView.as_view('request_reset'))
user.add_url_rule('/reset/<id>', view_func=PerformResetView.as_view('perform_reset'))
user.add_url_rule('/follow/<id>', view_func=follow, methods=('POST', ))
user.add_url_rule('/unfollow/<id>', view_func=unfollow, methods=('POST', ))
user.add_url_rule('/followers/<id>', view_func=followers)
user.add_url_rule('/<id>', view_func=read)
user.add_url_rule('/<id>/api-tokens', view_func=ApiTokenView.as_view('api_tokens'))
user.add_url_rule('/<id>/api-tokens/<jti>/revoke', view_func=api_token_revoke, methods=('POST',))
user.add_url_rule(rule='/sysadmin', view_func=sysadmin, methods=['POST'])
