import sys

_, flag, mapping_source_code = sys.argv

mapping = {(l := x.split(", '"))[1]: int(l[0]) for x in mapping_source_code.strip("{}").split("'}, {")}

print("{" + ", ".join(str(mapping[ch]) for ch in flag) + "}")
