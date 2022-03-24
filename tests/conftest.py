import binascii
import os
import time
import zlib
from io import StringIO, BytesIO

import pytest
from six import PY2

from procmon_parser import ProcmonLogsReader

if PY2:
    from unicodecsv import DictReader
    from codecs import BOM_UTF8
else:
    from csv import DictReader


RESOURCES_DIRECTORY = os.path.join(os.path.dirname(__file__), "resources")


def decompress_resource(resource_filename):
    with open(os.path.join(RESOURCES_DIRECTORY, resource_filename), "rb") as f:
        return zlib.decompress(f.read())


@pytest.fixture(scope='session')
def pml_logs_windows7_32bit():
    return decompress_resource("CompressedLogfileTests32bitUTCPML")


@pytest.fixture(scope='session')
def csv_logs_windows7_32bit():
    return decompress_resource("CompressedLogfileTests32bitUTCCSV")


@pytest.fixture(scope='session')
def pml_logs_windows10_64bit():
    return decompress_resource("CompressedLogfileTests64bitUTCPML")


@pytest.fixture(scope='session')
def csv_logs_windows10_64bit():
    return decompress_resource("CompressedLogfileTests64bitUTCCSV")


def get_pml_log_reader(pml_logs):
    pml_stream = BytesIO(pml_logs)
    start = time.time()
    pml_reader = ProcmonLogsReader(pml_stream)
    print("\nLoading PML reader took {} seconds\n".format(time.time() - start))
    return pml_reader


def get_csv_log_reader(csv_logs):
    if PY2:
        csv_stream = BytesIO(csv_logs)
        bom = csv_stream.read(len(BOM_UTF8))
        assert bom == BOM_UTF8, "Unexpected Procmon csv encoding"
        csv_reader = DictReader(csv_stream, encoding='utf-8')
    else:
        csv_stream = StringIO(csv_logs.decode('utf-8-sig'))
        csv_reader = DictReader(csv_stream)
    return csv_reader


@pytest.fixture(scope='function')
def pml_reader_windows7_32bit(pml_logs_windows7_32bit):
    return get_pml_log_reader(pml_logs_windows7_32bit)


@pytest.fixture(scope='function')
def csv_reader_windows7_32bit(csv_logs_windows7_32bit):
    return get_csv_log_reader(csv_logs_windows7_32bit)


@pytest.fixture(scope='function')
def pml_reader_windows10_64bit(pml_logs_windows10_64bit):
    return get_pml_log_reader(pml_logs_windows10_64bit)


@pytest.fixture(scope='function')
def csv_reader_windows10_64bit(csv_logs_windows10_64bit):
    return get_csv_log_reader(csv_logs_windows10_64bit)


@pytest.fixture(scope='function',
                params=[('CompressedLogFileUTC32FilesystemCSV', 'CompressedLogFileUTC32FilesystemPML'),
                        ('CompressedLogFileUTC64FilesystemCSV', 'CompressedLogFileUTC64FilesystemPML'),
                        ('CompressedLogFileUTC64ProcessCSV', 'CompressedLogFileUTC64ProcessPML'),
                        ('CompressedLogFileUTC64RegistryCSV', 'CompressedLogFileUTC64RegistryPML')])
def specific_events_logs_readers(request):
    return get_csv_log_reader(decompress_resource(request.param[0])), \
           get_pml_log_reader(decompress_resource(request.param[1]))


@pytest.fixture()
def raw_config_full():
    """a raw PMC binary data taken from my computer
    """
    return binascii.unhexlify('a000000010000000200000008000000043006f006c0075006d006e0073000000840057006400c80064009600'
                              '6400640064006400640064006400640064006400640064006400640064006400640064006400640064000000'
                              '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                              '000000000000000000000000000000000000000000000000000000002c000000100000002800000004000000'
                              '43006f006c0075006d006e0043006f0075006e00740000001b00000024010000100000002400000000010000'
                              '43006f006c0075006d006e004d006100700000008e9c0000759c0000779c0000879c0000799c0000749c0000'
                              '8c9c00008d9c0000e49c0000929c00007a9c0000849c0000839c0000939c0000889c0000949c0000959c0000'
                              '969c0000979c0000989c0000769c0000789c0000809c0000819c0000919c0000859c0000829c000000000000'
                              '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                              '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                              '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                              '0000000000000000000000006600000010000000280000003e000000440062006700480065006c0070005000'
                              '610074006800000043003a005c00570069006e0064006f00770073005c00530059005300540045004d003300'
                              '32005c00640062006700680065006c0070002e0064006c006c00200000001000000020000000000000004c00'
                              '6f006700660069006c00650000002c00000010000000280000000400000048006900670068006c0069006700'
                              '68007400460047000000000000002c00000010000000280000000400000048006900670068006c0069006700'
                              '6800740042004700000080ffff007c00000010000000200000005c0000004c006f00670046006f006e007400'
                              '0000080000000000000000000000000000009001000000000000000000004d00530020005300680065006c00'
                              '6c00200044006c00670000000000000000000000000000000000000000000000000000000000000000000000'
                              '00000000000088000000100000002c0000005c00000042006f006f006f006b006d00610072006b0046006f00'
                              '6e007400000008000000000000000000000000000000bc02000000000000000000004d005300200053006800'
                              '65006c006c00200044006c006700000000000000000000000000000000000000000000000000000000000000'
                              '000000000000000000002e000000100000002a0000000400000041006400760061006e006300650064004d00'
                              '6f00640065000000000000002a0000001000000026000000040000004100750074006f007300630072006f00'
                              '6c006c000000000000002e000000100000002a0000000400000048006900730074006f007200790044006500'
                              '7000740068000000c800000028000000100000002400000004000000500072006f00660069006c0069006e00'
                              '6700000000000000380000001000000034000000040000004400650073007400720075006300740069007600'
                              '6500460069006c007400650072000000010000002c00000010000000280000000400000041006c0077006100'
                              '790073004f006e0054006f007000000000000000360000001000000032000000040000005200650073006f00'
                              '6c00760065004100640064007200650073007300650073000000010000002600000010000000260000000000'
                              '000053006f007500720063006500500061007400680000008600000010000000260000006000000053007900'
                              '6d0062006f006c00500061007400680000007300720076002a00680074007400700073003a002f002f006d00'
                              '730064006c002e006d006900630072006f0073006f00660074002e0063006f006d002f0064006f0077006e00'
                              '6c006f00610064002f00730079006d0062006f006c0073000000000400001000000028000000d80300004600'
                              '69006c00740065007200520075006c006500730000000119000000759c000000000000011600000070007900'
                              '740068006f006e002e0065007800650000000000000000000000879c000006000000010800000070006d0063'
                              '0000000000000000000000759c0000000000000018000000500072006f0063006d006f006e002e0065007800'
                              '650000000000000000000000759c0000000000000018000000500072006f0063006500780070002e00650078'
                              '00650000000000000000000000759c000000000000001a0000004100750074006f00720075006e0073002e00'
                              '65007800650000000000000000000000759c000000000000001c000000500072006f0063006d006f006e0036'
                              '0034002e0065007800650000000000000000000000759c000000000000001c000000500072006f0063006500'
                              '78007000360034002e0065007800650000000000000000000000759c000000000000000e0000005300790073'
                              '00740065006d0000000000000000000000779c00000400000000100000004900520050005f004d004a005f00'
                              '00000000000000000000779c0000040000000010000000460041005300540049004f005f0000000000000000'
                              '000000789c00000400000000100000004600410053005400200049004f0000000000000000000000879c0000'
                              '05000000001a0000007000610067006500660069006c0065002e007300790073000000000000000000000087'
                              '9c000005000000000a00000024004d006600740000000000000000000000879c000005000000001200000024'
                              '004d00660074004d0069007200720000000000000000000000879c000005000000001200000024004c006f00'
                              '6700460069006c00650000000000000000000000879c0000050000000010000000240056006f006c0075006d'
                              '00650000000000000000000000879c0000050000000012000000240041007400740072004400650066000000'
                              '0000000000000000879c000005000000000c000000240052006f006f00740000000000000000000000879c00'
                              '0005000000001000000024004200690074006d006100700000000000000000000000879c000005000000000c'
                              '000000240042006f006f00740000000000000000000000879c00000500000000120000002400420061006400'
                              '43006c007500730000000000000000000000879c000005000000001000000024005300650063007500720065'
                              '0000000000000000000000879c00000500000000100000002400550070004300610073006500000000000000'
                              '00000000879c0000060000000010000000240045007800740065006e00640000000000000000000000929c00'
                              '00000000000014000000500072006f00660069006c0069006e00670000000000000000000000330000001000'
                              '00002e0000000500000048006900670068006c006900670068007400520075006c0065007300000001000000'
                              '00')