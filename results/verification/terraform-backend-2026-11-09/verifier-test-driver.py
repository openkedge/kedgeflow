from pathlib import Path
import importlib.util,json,shutil,tempfile
root=Path.cwd();spec=importlib.util.spec_from_file_location('backend_verifier',root/'scripts/verify-terraform-backend.py');v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
with tempfile.TemporaryDirectory(prefix='kf-backend-replay-') as temporary:
 out=Path(temporary)
 for name in ('lock','precheck','serial','lineage'):shutil.copytree(root/'.cache/terraform-backend-final2'/name,out/'cases'/name)
 positive=v.verify(out);assert positive['status']=='PASS'
 negatives=[]
 path=out/'cases/serial/state.json';saved=path.read_bytes();path.write_bytes(saved+b'\n')
 try:v.verify(out);raise AssertionError('corrupt state accepted')
 except ValueError as error:negatives.append({'case':'altered baseline bytes','refused':str(error)})
 path.write_bytes(saved)
 path=out/'cases/lock/sdk-native-report.json';saved=path.read_bytes();changed=json.loads(saved);changed['resumed']['wire'][-1]['method']='tools/call';path.write_text(json.dumps(changed))
 try:v.verify(out);raise AssertionError('redispatch history accepted')
 except ValueError as error:negatives.append({'case':'execution during cold recovery','refused':str(error)})
 path.write_bytes(saved)
 path=out/'cases/lineage/sdk-native-report.json';saved=path.read_bytes();changed=json.loads(saved);changed['intent']['state']='applied';path.write_text(json.dumps(changed))
 try:v.verify(out);raise AssertionError('promoted intent accepted')
 except ValueError as error:negatives.append({'case':'unknown intent promoted to applied','refused':str(error)})
 path.write_bytes(saved)
 result={'status':'PASS','positive':positive,'negative_replays':negatives,'negative_checks':len(negatives)}
 (root/'.cache/terraform-backend-verifier.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(result))
