# encoding: utf-8
from __future__ import annotations

import logging
from typing import Any, Union, cast, List

from flask import Blueprint
from flask.views import MethodView
from flask.wrappers import Response

import ckan.lib.app_globals as app_globals
import ckan.lib.base as base
from ckan.lib.helpers import helper_functions as h
import ckan.lib.navl.dictization_functions as dict_fns
from ckan.logic import (
    get_action,
    clean_dict,
    ValidationError,
    check_access,
    NotAuthorized,
    tuplize_dict,
    parse_params,
)
import ckan.model as model
import ckan.logic.schema
from ckan.common import _, config, request, current_user, session
from ckan.views.home import CACHE_PARAMETERS

from ckan.types import Context, Query


log = logging.getLogger(__name__)

admin = Blueprint("admin", __name__, url_prefix="/ckan-admin")


def _get_sysadmins() -> "Query[model.User]":
    q = model.Session.query(model.User).filter(
        # type_ignore_reason: incomplete SQLAlchemy types
        model.User.sysadmin.is_(True),  # type: ignore
        model.User.state == "active",
    )
    return q


def _get_config_options() -> dict[str, list[dict[str, str]]]:
    homepages = [
        {
            "value": "1",
            "text": _(
                "Introductory area, search, featured group and featured organization"
            ),
        },
        {
            "value": "2",
            "text": _(
                "Search, stats, introductory area, featured organization and featured group"
            ),
        },
        {"value": "3", "text": _("Search, introductory area and stats")},
    ]

    return dict(homepages=homepages)


def _get_config_items() -> list[str]:
    return [
        "ckan.site_title",
        "ckan.theme",
        "ckan.site_description",
        "ckan.site_logo",
        "ckan.site_about",
        "ckan.site_intro_text",
        "ckan.site_custom_css",
        "ckan.homepage_style",
    ]


@admin.before_request
def before_request() -> None:
    try:
        context = cast(
            Context,
            {
                "model": model,
                "user": current_user.name,
                "auth_user_obj": current_user,
            },
        )
        check_access("sysadmin", context)
        check_access("site_read", context)

        session.pop("_flashes", None)
        if not current_user or current_user.is_anonymous:
            h.flash_error(_("Not authorized to see this page"))
            return h.redirect_to("user.login")  # type: ignore
    except NotAuthorized:
        base.abort(403, _("Need to be system administrator to administer"))

    try:
        check_token = get_action("oidc_check_token")
        if check_token:
            check_token(context, {})
    except NotAuthorized:
        session.delete()
        return h.redirect_to("user.login")  # type: ignore


def index() -> str:
    data = dict(sysadmins=[a.name for a in _get_sysadmins()])
    return base.render("admin/index.html", extra_vars=data)


class ResetConfigView(MethodView):
    def get(self) -> Union[str, Response]:
        if "cancel" in request.args:
            return h.redirect_to("admin.config")
        return base.render("admin/confirm_reset.html", extra_vars={})

    def post(self) -> Response:
        # remove sys info items
        for item in _get_config_items():
            model.delete_system_info(item)
        # reset to values in config
        app_globals.reset()
        return h.redirect_to("admin.config")


class ConfigView(MethodView):
    def get(self) -> str:
        items = _get_config_options()
        schema = ckan.logic.schema.update_configuration_schema()
        data = {}
        for key in schema:
            data[key] = config.get(key)

        vars: dict[str, Any] = dict(data=data, errors={}, **items)

        return base.render("admin/config.html", extra_vars=vars)

    def post(self) -> Union[str, Response]:
        try:
            req: dict[str, Any] = request.form.copy()
            req.update(request.files.to_dict())
            data_dict = clean_dict(
                dict_fns.unflatten(
                    tuplize_dict(
                        parse_params(req, ignore_keys=CACHE_PARAMETERS)
                    )
                )
            )

            del data_dict["save"]
            config_option_update = get_action("config_option_update")
            config_option_update({"user": current_user.name}, data_dict)

        except ValidationError as e:
            items = _get_config_options()
            data = request.form
            errors = e.error_dict
            error_summary = e.error_summary
            vars = dict(
                data=data,
                errors=errors,
                error_summary=error_summary,
                form_items=items,
                **items,
            )
            return base.render("admin/config.html", extra_vars=vars)

        return h.redirect_to("admin.config")


class TrashView(MethodView):

    def __init__(self):
        self.deleted_packages = self._get_deleted_datasets()
        self.deleted_orgs = model.Session.query(model.Group).filter_by(
            state=model.State.DELETED, is_organization=True
        )
        self.deleted_groups = model.Session.query(model.Group).filter_by(
            state=model.State.DELETED, is_organization=False
        )

        self.deleted_entities = {
            "package": self.deleted_packages,
            "organization": self.deleted_orgs,
            "group": self.deleted_groups,
        }
        self.messages = {
            "confirm": {
                "all": _("Are you sure you want to purge everything?"),
                "package": _("Are you sure you want to purge datasets?"),
                "organization": _(
                    "Are you sure you want to purge organizations?"
                ),
                "group": _("Are you sure you want to purge groups?"),
            },
            "success": {
                "package": _("{number} datasets have been purged"),
                "organization": _("{number} organizations have been purged"),
                "group": _("{number} groups have been purged"),
            },
            "empty": {
                "package": _("There are no datasets to purge"),
                "organization": _("There are no organizations to purge"),
                "group": _("There are no groups to purge"),
            },
        }

    def _get_deleted_datasets(
        self,
    ) -> Union["Query[model.Package]", List[Any]]:
        if config.get("ckan.search.remove_deleted_packages"):
            return self._get_deleted_datasets_from_db()
        else:
            return self._get_deleted_datasets_from_search_index()

    def _get_deleted_datasets_from_db(self) -> "Query[model.Package]":
        return model.Session.query(model.Package).filter_by(
            state=model.State.DELETED
        )

    def _get_deleted_datasets_from_search_index(self) -> List[Any]:
        package_search = get_action("package_search")
        search_params = {
            "fq": "+state:deleted",
            "include_private": True,
        }
        base_results = package_search({"ignore_auth": True}, search_params)

        return base_results["results"]

    def get(self) -> str:
        ent_type = request.args.get("name")

        if ent_type:
            return base.render(
                "admin/snippets/confirm_delete.html",
                extra_vars={"ent_type": ent_type, "messages": self.messages},
            )

        data = dict(data=self.deleted_entities, messages=self.messages)
        return base.render("admin/trash.html", extra_vars=data)

    def post(self) -> Response:
        if "cancel" in request.form:
            return h.redirect_to("admin.trash")

        req_action = request.form.get("action", "")
        if req_action == "all":
            self.purge_all()
        elif req_action in ("package", "organization", "group"):
            self.purge_entity(req_action)
        else:
            h.flash_error(_("Action not implemented."))
        return h.redirect_to("admin.trash")

    def purge_all(self):
        actions = ("dataset_purge", "group_purge", "organization_purge")
        entities = (
            self.deleted_packages,
            self.deleted_groups,
            self.deleted_orgs,
        )

        for action, deleted_entities in zip(actions, entities):
            for entity in deleted_entities:
                ent_id = entity.id if hasattr(entity, "id") else entity["id"]  # type: ignore
                act = get_action
                act(action)({"user": current_user.name}, {"id": ent_id})
            model.Session.remove()
        h.flash_success(_("Massive purge complete"))

    def purge_entity(self, ent_type: str):
        entities = self.deleted_entities[ent_type]
        number = (
            len(entities) if isinstance(entities, list) else entities.count()
        )

        for ent in entities:
            entity_id = ent.id if hasattr(ent, "id") else ent["id"]
            action = get_action(self._get_purge_action(ent_type))
            action({"user": current_user.name}, {"id": entity_id})

        model.Session.remove()
        h.flash_success(
            self.messages["success"][ent_type].format(number=number)
        )

    @staticmethod
    def _get_purge_action(ent_type: str) -> str:
        actions = {
            "package": "dataset_purge",
            "organization": "organization_purge",
            "group": "group_purge",
        }

        return actions[ent_type]


admin.add_url_rule("/", view_func=index, methods=["GET"], strict_slashes=False)
admin.add_url_rule(
    "/reset_config", view_func=ResetConfigView.as_view("reset_config")
)
admin.add_url_rule("/config", view_func=ConfigView.as_view("config"))
admin.add_url_rule("/trash", view_func=TrashView.as_view("trash"))
