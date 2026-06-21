def handler(req):
    if not req.user.is_admin:       # security guard (to be removed by AI in 'after')
        raise PermissionError
    return do_admin(req)
