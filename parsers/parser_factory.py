from config.constants import LogSource
from parsers.linux_parser import LinuxParser
from parsers.apache_parser import ApacheParser
from parsers.windows_parser import WindowsParser
from parsers.aws_parser import AWSParser

class ParserFactory:
    @staticmethod
    def get_parser(log_source: LogSource):

        if log_source == LogSource.LINUX:
            return LinuxParser()

        elif log_source == LogSource.APACHE:
            return ApacheParser()

        elif log_source == LogSource.WINDOWS:
            return WindowsParser()

        elif log_source == LogSource.AWS:
            return AWSParser()

        raise ValueError(
            f"No parser implemented for '{log_source.value}'."
        )