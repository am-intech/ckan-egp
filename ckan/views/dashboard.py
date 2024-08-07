# encoding: utf-8
from __future__ import annotations

import logging
from typing import Any, cast

from flask import Blueprint

import ckan.lib.base as base
from ckan.lib.helpers import helper_functions as h
import ckan.logic as logic
import ckan.model as model
from ckan.common import _, current_user
from ckan.views.user import _extra_template_variables
from ckan.types import Context

log = logging.getLogger(__name__)

dashboard = Blueprint('dashboard', __name__, url_prefix='/dashboard')


@dashboard.before_request
def before_request() -> None:
    if not current_user or current_user.is_anonymous:
        h.flash_error(_('Not authorized to see this page'))
        return h.redirect_to('user.login')  # type: ignore

    try:
        context = cast(Context, {
            "model": model,
            "user": current_user.name,
            "auth_user_obj": current_user
        })
        logic.check_access('site_read', context)
    except logic.NotAuthorized:
        base.abort(403, _('Not authorized to see this page'))
    return None


def datasets() -> str:
    context = cast(Context, {
        'for_view': True,
        'user': current_user.name,
        'auth_user_obj': current_user
    })
    data_dict: dict[str, Any] = {
        'user_obj': current_user,
        'include_datasets': True}
    extra_vars = _extra_template_variables(context, data_dict)
    return base.render('user/dashboard_datasets.html', extra_vars)


def organizations() -> str:
    context = cast(Context, {
        'for_view': True,
        'user': current_user.name,
        'auth_user_obj': current_user
    })
    data_dict = {'user_obj': current_user}
    extra_vars = _extra_template_variables(context, data_dict)
    return base.render('user/dashboard_organizations.html', extra_vars)


def groups() -> str:
    context = cast(Context, {
        'for_view': True,
        'user': current_user.name,
        'auth_user_obj': current_user
    })
    data_dict = {'user_obj': current_user}
    extra_vars = _extra_template_variables(context, data_dict)
    return base.render('user/dashboard_groups.html', extra_vars)


dashboard.add_url_rule('/datasets', view_func=datasets)
dashboard.add_url_rule('/groups', view_func=groups)
dashboard.add_url_rule('/organizations', view_func=organizations)
