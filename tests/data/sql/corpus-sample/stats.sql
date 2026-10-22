select owner, table_name, num_rows, mycompany_fn(last_analyzed) as age
from dba_tab_statistics
where owner = :OWNER
