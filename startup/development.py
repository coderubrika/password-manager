from app import app


def development(cfg):
    print('startup by "Development" mode')
    app.start()