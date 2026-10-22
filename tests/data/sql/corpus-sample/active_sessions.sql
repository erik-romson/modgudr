select sid, serial#, username, status
from v$session
where username = :USERNAME
order by sid
fetch first 10 rows only
