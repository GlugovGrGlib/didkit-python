from python_django.settings import KEY_PATH
from datetime import datetime, timedelta
import didkit
import json
import uuid


async def issueCredential(request):
    with open(KEY_PATH, "r") as f:
        key = f.readline()

    did_key = request.POST.get('subject_id', didkit.key_to_did("key", key))
    verification_method = await didkit.key_to_verification_method("key", key)
    issuance_date = datetime.utcnow().replace(microsecond=0)
    expiration_date = issuance_date + timedelta(weeks=24)

    credential = {
        "id": "urn:uuid:" + str(uuid.uuid4()),
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "type": ["VerifiableCredential"],
        "issuer": {
            "id": did_key,
        },
        "issuanceDate": issuance_date.isoformat() + "Z",
        "expirationDate": expiration_date.isoformat() + "Z",
        "credentialSubject": {
            "id": "urn:uuid:" + str(uuid.uuid4()),
        },
    }

    didkit_options = {
        # "proofPurpose": "assertionMethod",
        # "verificationMethod": verification_method,
        "type": "Ed25519Signature2020",
        # "challenge": 
    }

    credential = await didkit.issue_credential(
        json.dumps(credential),
        json.dumps(didkit_options),
        key)
    await didkit.verify_credential(credential, '{}')
    return json.loads(credential)
