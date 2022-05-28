class AddressUtils(object):
    def __init__(self, unpack_size):
        self.unpack_size = unpack_size

    def section_get_ptr_at_address(self, section, address, alignment):
        start = section.header.sh_addr
        end = start + section.header.sh_size
        assert address < end, 'Error, address: {} out of range'.format(address)
        index_start = address - start
        index_end = index_start + alignment

        return self.unpack_size(
            size=alignment,
            data=section.data()[index_start:index_end]
        )
