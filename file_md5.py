import hashlib
def validate_file_md5_hash(file, original_hash):
    """ Returns true if file MD5 hash matches with the provided one, false otherwise. """

    if get_file_md5_hash(file) == original_hash:
        print ("Hash file is OK")
        return True
    else:
        print ("Hash file is NOT VALID")
        return False

def get_file_md5_hash(file):
    """ Returns file MD5 hash"""

    md5_hash = hashlib.md5()
    for bytes in read_bytes_from_file(file):
        md5_hash.update(bytes)

    return md5_hash.hexdigest()

def read_bytes_from_file(file, chunk_size = 8100):
    """ Read bytes from a file in chunks. """

    with open(file, 'rb') as file:
        while True:
            chunk = file.read(chunk_size)

            if chunk:
                    yield chunk
            else:
                break
