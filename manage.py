from config import *

def start():
    if startup_mode == 'development':
        from startup.development import development
        development(config[startup_mode])

    elif startup_mode == 'production':
        from startup.production import production
        production(config[startup_mode])

    elif startup_mode == 'test':
        from startup.test import test
        test(config[startup_mode])

    elif startup_mode == 'stage':
        from startup.stage import stage
        stage(config[startup_mode])

    elif startup_mode == 'init':
        from startup.init import init
        init(config[startup_mode])

    elif startup_mode == 'sandbox':
        from startup.sandbox import sandbox
        sandbox(config[startup_mode])

    else:
        from startup.defualt import default
        default()


if __name__ == '__main__':
    start()
