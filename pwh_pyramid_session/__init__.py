import json

from base64 import urlsafe_b64encode
from binascii import unhexlify
from decorator import decorator
from pyramid.httpexceptions import HTTPFound, HTTPForbidden
from pyramid_nacl_session import EncryptedCookieSessionFactory
from sqlalchemy import and_


UserModel = None
login_route = None
store_current = True


def encode_route(request):
    """Jinja2 filter that returns the current route as a JSON object, which is then URL-safe base64 encoded."""
    if request.matched_route:
        data = {'route': request.matched_route.name,
                'params': request.matchdict,
                'query': list(request.params.items())}
        return urlsafe_b64encode(json.dumps(data).encode('utf-8')).decode()
    return None


def get_current_user(request):
    """Get the current user from the database based on the user id set in the request's session.

    :param request: The request used to access the session and database
    :type request: :class:`~pyramid.request.Request`
    """
    if 'user-id' in request.session and hasattr(request, 'dbsession'):
        return request.dbsession.query(UserModel).filter(and_(UserModel.id == request.session['user-id'],
                                                              UserModel.status == 'active')).first()
    return None


def require_logged_in():
    """Pyramid decorator to check the request is logged in."""
    global login_route

    def handler(f, *args, **kwargs):
        if args[0].current_user is not None:
            return f(*args, **kwargs)
        elif login_route is not None:
            if store_current:
                raise HTTPFound(args[0].route_url(login_route, _query={'redirect': encode_route(args[0])}))
            else:
                raise HTTPFound(args[0].route_url(login_route))
        else:
            raise HTTPForbidden()
    return decorator(handler)


def logged_in(request):
    """Jinja2 filter that checks if the current user is logged in."""
    return request.current_user is not None


def includeme(config):
    """Setup the session handling in the configuration."""
    global UserModel, login_route, store_current
    settings = config.get_settings()
    UserModel = settings['pwh.pyramid_session.user']
    login_route = settings['pwh.pyramid_session.login_route']
    if 'pwh.pyramid_session.store_current' in settings and \
            settings['pwh.pyramid_session.store_current'].lower() == 'false':
        store_current = False

    secret = unhexlify(settings['pwh.pyramid_session.secret'].strip())
    factory = EncryptedCookieSessionFactory(secret, cookie_name=settings['pwh.pyramid_session.cookie_name'],
                                            timeout=int(settings['pwh.pyramid_session.timeout'])
                                            if 'pwh.pyramid_session.timeout' in settings else 1200)
    config.set_session_factory(factory)

    config.add_request_method(
        get_current_user,
        'current_user',
        reify=True
    )

    config.set_default_csrf_options(require_csrf=True)

    config.get_jinja2_environment().filters['logged_in'] = logged_in
