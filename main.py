import re
import json

"""
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\""
    h : host (IP address of the client)
    l : identity_check
    u : userid (userid of the person requesting)
    t : time
    r : request line
    s : status code
    b : bytes length

Example:

10.0.0.1 - - [25/May/2014:06:47:15] "GET HTTP/1.0" 200 126 "-" "Apache/2.2.2"

"""


def parse_access_log(log):
    # split log by " " 3 times to get host, identity_check, userid
    split_log = log.split(" ", 3)
    host = split_log[0]
    userid = split_log[2]

    # remains [25/May/2014:06:47:15] "GET HTTP/1.0" 200 126 "-" "Apache/2.2.2"
    remains = split_log[3]

    # get time using regex and then remove it from log
    time = re.search(r"\[(.*?)\]", remains).group(1)
    remains = remains.replace(f"[{time}]", "").strip()

    # split log by " then  remove none or space items from list
    remains = remains.split('"')
    remains = filter((lambda x: x not in ("", " ")), remains)
    remains = list(remains)

    # remains : ['GET HTTP/1.0', ' 200 126 ', '-', 'Apache/2.2.22']
    request_line = remains[0]
    status_code = remains[1].strip().split()[0]
    bytes_length = remains[1].strip().split()[1]
    referer = remains[2]
    user_agent = remains[3]

    return (
        host,
        userid,
        time,
        request_line,
        status_code,
        bytes_length,
        referer,
        user_agent,
    )


def init_data(host, request_method, status_code, user_agent):
    return {
        "ip": host,
        "method": {
            f"{request_method}": {
                "count": 1,
                "status_code": {f"{status_code}": 1},
            },
        },
        "user_agent": [user_agent],
    }


def analyze_access(host, request_line, status_code, user_agent, result):
    request_method = request_line.split()[0]

    # init analysis data for new accessed host
    if host not in result:
        result[host] = init_data(host, request_method, status_code, user_agent)

    else:  # update analysis data for existed host
        methods = result[host]["method"]

        # If host never use this request method
        if request_method not in methods:
            methods[f"{request_method}"] = {
                "count": 1,
                "status_code": {f"{status_code}": 1},
            }

        else:
            methods[f"{request_method}"]["count"] += 1

            # count = 1 when status code existed else increasing 1
            statuses = methods[f"{request_method}"]

            if status_code not in statuses:
                statuses[f"{status_code}"] = 1
            else:
                statuses[f"{status_code}"] += 1

            # save values of status code to method
            methods[f"{request_method}"] = statuses

        result[host]["method"] = methods  # save values of method to host data

        # update user_agent
        if user_agent != "-" and user_agent not in result[host]["user_agent"]:
            result[host]["user_agent"].append(user_agent)


def main():
    result = {}
    with open("access.log") as f:
        # lines = [line.rstrip('\n') for line in f]
        for line in f:
            (
                host,
                userid,
                time,
                request_line,
                status_code,
                bytes_length,
                referer,
                user_agent,
            ) = parse_access_log(line.rstrip())

            analyze_access(host, request_line, status_code, user_agent, result)
    print(json.dumps(result, indent=4))


main()
