import sys
from networksecurity.logging import logger


class NetworkSecurityException(Exception):
    def __init__(self, error_message, error_detail: sys):
        super().__init__(error_message)
        self.error_message = str(error_message)
        self.error_detail = error_detail
        self.lineno = None
        self.file_name = "unknown"

        if error_detail is not None and hasattr(error_detail, "exc_info"):
            _, _, exc_tb = error_detail.exc_info()
            if exc_tb is not None:
                self.lineno = exc_tb.tb_lineno
                self.file_name = exc_tb.tb_frame.f_code.co_filename

    def __str__(self):
        return "Error occured in python script name [{0}] line number [{1}] error message [{2}]".format(
            self.file_name, self.lineno, self.error_message
        )


if __name__ == "__main__":
    try:
        logger.logging.info("Entered the try block")
        a = 1 / 0
        print(a)
    except Exception as e:
        raise NetworkSecurityException(e, sys) from e