def extract_text_between(stream, start_s, end_s, times=-1):
    streams = []
    start = stream.find(start_s)
    i = 0
    while start >= 0 and i != times:
        start += len(start_s)
        end = stream[start:].find(end_s)

        if end < 0:
            raise Exception("Infinite loop detected")
        end += start
        sub = stream[start:end]
        stream = stream[end + len(end_s):]
        streams.append(sub)
        start = stream.find(start_s)
        i += 1
    if times == 1:
        return streams[0]
    return streams
