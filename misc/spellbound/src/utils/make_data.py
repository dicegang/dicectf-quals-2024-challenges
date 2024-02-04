import json

with open("raw.txt") as f:
    all_data = []

    data = None
    state = None
    previous_line = None
    
    current = ""
    for line in f:
        line = line.rstrip("\n")
        if line == "":
            continue

        if line.startswith("Pronunciation: "):
            if data:
                all_data.append(data)
            
            data = {
                "word": previous_line.strip(),
                "pronunciation": "",
                "description": "",
                "seen": "",
                "etymology": "",
                "notes": "",
            }
            current = line[len("Pronunciation: "):]
            state = "P"
        elif line.startswith("Description:"):
            if state == "P":
                data["pronunciation"] = current.strip()
                current = line[len("Description: "):]
                state = "D"
        elif line.startswith("Seen/Mentioned: "):
            if state == "D":
                data["description"] = current.strip()
                current = line[len("Seen/Mentioned: "):]
                state = "S"
        elif line.startswith("Suggested Etymology: "):
            if state == "S":
                data["seen"] = current.strip()
                current = line[len("Suggested Etymology: "):]
                state = "E"
        elif line.startswith("Notes: "):
            if state == "E":
                data["etymology"] = current.strip()
                current = line[len("Notes: "):]
                state = "N"
        else:
            current += line

        previous_line = line
    
    all_data.append(data)

with open("dictionary.json", "w") as f:
    f.write(json.dumps(all_data))

with open("words.json", "w") as f:
    f.write(json.dumps([d["word"] for d in all_data]))