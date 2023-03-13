# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" We use x-goog-api-client header to report metrics. This module provides
the helper methods to construct x-goog-api-client header.
"""

import platform

from google.auth import version

AUTH_REQUEST_TYPE_NONE = "auth-request-type/none"
AUTH_REQUEST_TYPE_ACCESS_TOKEN = "auth-request-type/access-token"
AUTH_REQUEST_TYPE_ID_TOKEN = "auth-request-type/id-token"

CRED_TYPE_USER = "cred-type/user"
CRED_TYPE_REAUTH = "cred-type/reauth"
CRED_TYPE_SA_ASSERTION = "cred-type/sa-assertion"
CRED_TYPE_SA_JWT = "cred-type/sa-jwt"
CRED_TYPE_SA_MDS = "cred-type/sa-mds"
CRED_TYPE_SA_IMPERSONATE = "cred-type/sa-impersonate"

AUTH = "auth/" + version.__version__
LANG_PYTHON = "gl-python/" + platform.python_version()
SELF_SIGNED_JWT = AUTH + " auth-request-type/access-token cred-type/sa-jwt"

API_CLIENT_HEADER = "x-goog-api-client"


def create_header(auth_request_type, cred_type):
    """Create the x-goog-api-client header value.

    Args:
        auth_request_type (str): The auth-request-type token and value.
        cred_type (str): The cred-type token and value.
    
    Returns:
        str: The x-goog-api-client header value.
    """
    return LANG_PYTHON + " " + AUTH + " " + auth_request_type + " " + cred_type


def create_header_mds_ping():
    """Returns the header value for metadata server ping. e.g.
    "gl-python/3.6 auth/2.6.1 auth-request-type/none cred-type/sa-mds"
    """
    return create_header(AUTH_REQUEST_TYPE_NONE, CRED_TYPE_SA_MDS)


def create_header_mds_access_token():
    """Returns the header value for metadata server access token request. e.g.
    "gl-python/3.6 auth/2.6.1 auth-request-type/access-token cred-type/sa-mds"
    """
    return create_header(AUTH_REQUEST_TYPE_ACCESS_TOKEN, CRED_TYPE_SA_MDS)


def create_header_mds_id_token():
    """Returns the header value for metadata server ID token request. e.g.
    "gl-python/3.6 auth/2.6.1 auth-request-type/id-token cred-type/sa-mds"
    """
    return create_header(AUTH_REQUEST_TYPE_ACCESS_TOKEN, CRED_TYPE_SA_MDS)


def create_header_user():
    """Returns the header value for user cred token request. e.g.
    "gl-python/3.6 auth/2.6.1 auth-request-type/none cred-type/user"
    """
    return create_header(AUTH_REQUEST_TYPE_NONE, CRED_TYPE_USER)


def create_header_reauth():
    """Returns the header value for reauth related requests. e.g.
    "gl-python/3.6 auth/2.6.1 auth-request-type/none cred-type/reauth"
    """
    return create_header(AUTH_REQUEST_TYPE_NONE, CRED_TYPE_REAUTH)


def create_header_sa_assertion_access_token():
    """Returns the header value for service account access token request using
    assertion flow. e.g.
    "gl-python/3.6 auth/2.6.1 auth-request-type/access-token " +
    "cred-type/sa-assertion"
    """
    return create_header(AUTH_REQUEST_TYPE_ACCESS_TOKEN, CRED_TYPE_SA_ASSERTION)


def create_header_sa_assertion_id_token():
    """Returns the header value for service account id token request using
    assertion flow. e.g.
    "gl-python/3.6 auth/2.6.1 auth-request-type/id-token " +
    "cred-type/sa-assertion"
    """
    return create_header(AUTH_REQUEST_TYPE_ID_TOKEN, CRED_TYPE_SA_ASSERTION)


def create_header_sa_impersonate_access_token():
    """Returns the header value for impersonated cred access token request.
    e.g.
    "gl-python/3.6 auth/2.6.1 auth-request-type/access-token " +
    "cred-type/sa-impersonate"
    """
    return create_header(AUTH_REQUEST_TYPE_ACCESS_TOKEN, CRED_TYPE_SA_IMPERSONATE)


def create_header_sa_impersonate_id_token():
    """Returns the header value for impersonated cred id token request.
    e.g.
    "gl-python/3.6 auth/2.6.1 auth-request-type/id-token " +
    "cred-type/sa-impersonate"
    """
    return create_header(AUTH_REQUEST_TYPE_ID_TOKEN, CRED_TYPE_SA_IMPERSONATE)
