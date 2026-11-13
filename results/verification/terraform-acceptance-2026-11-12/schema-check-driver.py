"""Schema shape checks only; no deployed facts or signature acceptance."""
import argparse
import copy
import json
from pathlib import Path
from jsonschema import Draft202012Validator
p=argparse.ArgumentParser();p.add_argument('--schema',type=Path,required=True);p.add_argument('--records',type=Path,required=True);a=p.parse_args()
schema=json.loads(a.schema.read_text());Draft202012Validator.check_schema(schema);v=Draft202012Validator(schema);records=[]
for name in ('deployment.json','trust.json','evidence.json','approvals.json'):
 body=json.loads((a.records/name).read_text());records.append(body)
 if name=='evidence.json':records.extend(body['gates'])
 if name=='approvals.json':records.extend(body['approvals'])
for body in records:v.validate(body)
checks=[];base=json.loads((a.records/'deployment.json').read_text());extra=copy.deepcopy(base);extra['extra']=True;checks.append(extra)
obs=json.loads((a.records/'evidence.json').read_text())['gates'][0]
for value in ('local_fixture','unqualified'):
 x=copy.deepcopy(obs);x['scope']=value;checks.append(x)
x=copy.deepcopy(obs);x['checks'][0]['result']='unknown';checks.append(x)
x=copy.deepcopy(obs);x['checks'][1]=copy.deepcopy(x['checks'][0]);checks.append(x)
x=copy.deepcopy(obs);x['checks'].pop();checks.append(x)
x=copy.deepcopy(base);x['expires_at']=9007199254740993;checks.append(x)
x=copy.deepcopy(base);x['scope']['target_atomic']=True;checks.append(x)
for body in checks:assert not v.is_valid(body)
print(json.dumps({'status':'PASS','schema_records':len(records),'negative_schema_records':len(checks),'scope':'synthetic closed-shape tests; no deployed acceptance'},indent=2))
