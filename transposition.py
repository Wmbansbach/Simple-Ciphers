# Source Guide to Network Security
import binascii

class XPC:
    ''' 
    Transposition Cipher
    Based off of key pattern provided
    1 to 4, 2 to 8, 3 to 1, 4 to 5, 5 to 7, 6 to 2, 7 to 6, 8 to 3
    Messages are batched into blocks of 8 characters
    '''
    def __init__(self):
        pass

    def process(self, mode, msg):
        if mode == 1:
            return self.encrypt(msg)
        else:
            return self.decrypt(msg)
    
    def condense(self, buffer):
        ## Condense buffered list into the ciphertext string
        cipher = ""
        for ind in buffer:
            for val in ind:
                cipher += val
        return cipher
        
    def batch(self, msg):
        ''' 
        Batch msg into blocks of 8
        Pad uneven blocks with A characters
        '''
        count = 0
        msg_list = list(msg)
        c_list = []

        while count < len(msg_list)/8:
            t = (count * 8)
            c_list.append(msg_list[0 + t: 8 + t])
            count += 1

        # --------- Pad Batch ---------------
        c_list_len = len(c_list)
        stlen = c_list[c_list_len - 1]
        if len(stlen) < 8:
            buff_str = ["A"] * (7 - len(stlen))
            c_list[c_list_len - 1].append(">")
            for i in buff_str:
                c_list[c_list_len - 1].append(i)
        return c_list

    def encrypt(self, pt):
        msg = self.batch(pt)
        buffer = []
        for c_list in msg:
            try:
                c_list[0], c_list[3] = c_list[3], c_list[0]
                c_list[1], c_list[7] = c_list[7], c_list[1]
                c_list[2], c_list[0] = c_list[0], c_list[2]
                c_list[3], c_list[4] = c_list[4], c_list[3]
                c_list[4], c_list[6] = c_list[6], c_list[4]
                c_list[5], c_list[1] = c_list[1], c_list[5]
                c_list[6], c_list[5] = c_list[5], c_list[6]
                c_list[7], c_list[2] = c_list[2], c_list[7]
            except IndexError:
                pass
            finally:
                buffer.append(c_list)
        return self.condense(buffer)


    def decrypt(self, ct):
        msg = self.batch(ct)
        buffer = []
        for c_list in msg:
            try:
                c_list[2], c_list[7] = c_list[7], c_list[2] 
                c_list[5], c_list[6] = c_list[6], c_list[5]
                c_list[1], c_list[5] = c_list[5], c_list[1]
                c_list[6], c_list[4] = c_list[4], c_list[6]
                c_list[4], c_list[3] = c_list[3], c_list[4]
                c_list[0], c_list[2] = c_list[2], c_list[0]
                c_list[7], c_list[1] = c_list[1], c_list[7]
                c_list[3], c_list[0] = c_list[0], c_list[3]
            except IndexError:
                pass
            finally:
                buffer.append(c_list)
            
        return self.condense(buffer).split(">")[0]


class XOR:
    '''
    Exclusive OR (XOR) Cipher
    Block sizes based on input
    '''
    def __init__(self):
        self.data = any
        pass
    
    def batch(self, msg, key):
        m_buffer = ""
        k_buffer = ""
        
        #-----Xfer input into binary-----#
        for c in msg:
            m_buffer += bin(ord(c))[2:].zfill(8)
        for k in key:
            k_buffer += bin(ord(k))[2:].zfill(8)

        m_buffer_len = len(m_buffer)
        k_buffer_len = len(k_buffer)        

        #-------Pad buffer-------#
        if m_buffer_len > k_buffer_len:
            k_buffer += "".zfill(m_buffer_len - k_buffer_len)
        else:
            m_buffer += "".zfill(k_buffer_len - m_buffer_len)

        return {"msg": m_buffer, "key": k_buffer}

    def condense(self, msg):
        ## Xfer processed value back to ascii character
        self.data = {}
        return binascii.unhexlify("%x" % int("0b" + msg[1:], 2)).decode("ascii")

    def process(self, mode, msg, key):
        self.data = self.batch(msg, key)
        if mode == 1:
            return self.encrypt(self.data)
        else:
            return self.decrypt(self.data)

    def encrypt(self, msg_data):
        cipher = ""
        for m, k in zip(msg_data["msg"], msg_data["key"]):
            if m == k:
                cipher += "0"
            else:
                cipher += "1"

        return self.condense(cipher)

    def decrypt(self, msg_data):
        msg = ""
        for m, k in zip(msg_data["msg"], msg_data["key"]):
            if m == k:
                msg += "0"
            else:
                msg += "1"
        return self.condense(msg)

