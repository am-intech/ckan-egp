# encoding: utf-8

from flask import Blueprint

import ckan.lib.base as base
from ckan.lib.helpers import helper_functions as h
from ckan.common import _, request
from ckan.types import Response

util = Blueprint('util', __name__)


def internal_redirect() -> Response:
    ''' Redirect to the url parameter.
    Only internal URLs are allowed'''

    url = request.form.get('url') or request.args.get('url')
    if not url:
        base.abort(400, _('Missing Value') + ': url')

    url = url.replace('\r', ' ').replace('\n', ' ').replace('\0', ' ')
    if h.url_is_local(url):
        return h.redirect_to(url)
    else:
        base.abort(403, _('Redirecting to external site is not allowed.'))


def primer() -> str:
    ''' Render all HTML components out onto a single page.
    This is useful for development/styling of CKAN. '''

    return base.render('development/primer.html')


util.add_url_rule(
    '/util/redirect', view_func=internal_redirect, methods=('GET', 'POST',))
util.add_url_rule('/testing/primer', view_func=primer)
