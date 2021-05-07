class InvalidConfigFile(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return "There seems to be a problem with your configuration file. \nInspection reports: \"" + self.message + "\""


class InvalidRadixException:
    pass