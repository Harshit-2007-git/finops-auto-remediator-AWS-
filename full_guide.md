# Running the FinOps Auto-Remediation project on a real AWS account

Everything in order: **[C]** = do it in the AWS web console, **[T]** = do it in your laptop terminal (Windows PowerShell).

> **Honest status:** the project and this guide were checked offline with moto, which does not enforce IAM. Nobody (including me) has run the deployed stack on a real account yet, so do the whole thing once as a **rehearsal the day before** your demo.
>
> **Important:** the project's own `scripts/seed.py` does **not** work on real AWS (it uses a fake AMI id, and the volumes land in a different Availability Zone from the instances). Use the `seed_real_aws.py` file that came with this guide instead. I tested its logic offline only.

**What you will end up showing:** the scanner Lambda automatically stops idle dev/QA instances and deletes an orphan dev volume; a risky prod resource triggers an approval email; every action appears in **CloudTrail Event History**; the audit log in DynamoDB is KMS-encrypted and only the auditor role can decrypt it.

**Cost:** 5 x t3.micro for a few hours, 3 x 1 GB volumes, one tiny snapshot, and one KMS key (about $1/month prorated). Lambda, DynamoDB, SNS and CloudWatch stay inside the free allowances at this volume. Torn down the same day it is typically cents to a couple of dollars. Check the AWS pricing pages for your region.

---

## Part 1: AWS console setup (one time)

1. **[C] Sign in** to your AWS account (the root user or an admin). In the top-right region selector choose **Asia Pacific (Mumbai) ap-south-1**. Use this region for everything.
2. **[C] Set a budget alert first.** Search "Billing and Cost Management" -> **Budgets** -> **Create budget** -> **Monthly cost budget**, amount **$5**, enter your email, create. (Cost data can lag, so this is a safety net, not a stop button.)
3. **[C] Create a deploy user.** Search **IAM** -> **Users** -> **Create user**.
   - User name: `finops-deployer`.
   - **Set permissions** -> **Attach policies directly** -> tick **AdministratorAccess** -> Next -> **Create user**. (Admin is acceptable for a short-lived demo user; you will delete its key at the end.)
4. **[C] Create its access key.** Open the user -> **Security credentials** -> **Create access key** -> use case **Command Line Interface (CLI)** -> tick the acknowledgement -> Next -> **Create access key**. Copy the **Access key ID** and **Secret access key** now (the secret is shown once).
   - Never use root-user keys. Never put these keys in the project or in a screenshot.

## Part 2: Install the tools on your laptop

5. **[T]** Open PowerShell and run:
   ```powershell
   winget install Amazon.AWSCLI
   winget install Amazon.SAM-CLI
   winget install Docker.DockerDesktop
   ```
6. **Close and reopen PowerShell**, restart the laptop if Docker asks, then **start Docker Desktop and wait until it says it is running**.
7. **[T]** Check everything:
   ```powershell
   aws --version
   sam --version
   docker --version
   python --version
   ```
   All four must print a version. The project uses Python 3.12.

## Part 3: Connect the terminal to AWS

8. **[T]**
   ```powershell
   aws configure
   ```
   Enter the Access key ID, the Secret access key, region `ap-south-1`, output format `json`.
9. **[T]** Verify:
   ```powershell
   aws sts get-caller-identity
   ```
   It must show your account id and `.../finops-deployer`.

## Part 4: Prepare the project

10. **[T]** Unzip the project, then in PowerShell go to its folder (the one containing `template.yaml`):
    ```powershell
    cd C:\path\to\FinOpsRemediation
    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements-dev.txt
    python -m pytest tests -q
    ```
    All tests should pass (127 in the version I checked). If PowerShell blocks the activate script, run `Set-ExecutionPolicy -Scope Process Bypass` and retry.
11. **[T]** Copy `seed_real_aws.py` (from this guide) into the project root folder next to `template.yaml`.

## Part 5: Deploy the stack

12. **[T]** Build. Docker must be running, because the `cryptography` package has to be built for Lambda's Linux:
    ```powershell
    sam build --use-container
    ```
    The first run downloads images and can take several minutes.
13. **[T]** Deploy. The stack creates a named IAM role, so this capability flag is required:
    ```powershell
    sam deploy --guided --capabilities CAPABILITY_NAMED_IAM
    ```
    Answer the prompts:
    - Stack Name: `finops-remediation`
    - AWS Region: `ap-south-1`
    - Parameter KMSKeyAliasName: press Enter (default `finops-key`)
    - Parameter EscalationEmail: **your real email** (approval emails go here)
    - Confirm changes before deploy: `y`
    - Allow SAM CLI IAM role creation: `y`
    - Disable rollback: `n`
    - Save arguments to configuration file: `y` (accept the defaults)
    - If asked whether a function without authorization is OK: `y` (the approval link is protected by a signed token, not by AWS auth)
    When it shows the change set, answer `y` to deploy. It takes a few minutes.
14. **[T]** Save the outputs (you need `AuditorRoleArn` later):
    ```powershell
    aws cloudformation describe-stacks --stack-name finops-remediation --region ap-south-1 --query "Stacks[0].Outputs" --output table
    ```
15. **[C] Confirm the email subscription.** Check your inbox (and spam) for "AWS Notification - Subscription Confirmation" and click **Confirm subscription**. In the console, **SNS -> Subscriptions** should show status **Confirmed**.
16. **[T] Create the signing secret.** CloudFormation cannot create SecureString parameters, so do it by hand. **Do not add `--key-id`**, because the Lambda roles are deliberately not allowed to use the project's own KMS key for this and the call would fail:
    ```powershell
    $secret = python -c "import secrets; print(secrets.token_hex(32))"
    aws ssm put-parameter --name /finops/hmac-secret --value $secret --type SecureString --overwrite --region ap-south-1
    ```
17. **[C] Sanity check what was created:** open **Lambda** (functions `finops-scanner`, `finops-remediator`, `finops-escalator`, `finops-approver`), **DynamoDB** (table `finops-audit-log`), **KMS -> Customer managed keys** (alias `finops-key`).

## Part 6: Create the demo resources

18. **[T]**
    ```powershell
    python seed_real_aws.py ap-south-1
    ```
    It launches 5 t3.micro instances and 3 x 1 GB volumes (all tagged `Project=finops-demo`) in one Availability Zone and attaches `vol-prod-data`.
19. **[C]** Open **EC2 -> Instances** and **Volumes** and confirm: `dev-api-01`, `qa-runner-01`, `qa-loadtest-02` (tag `keep=true`), `prod-report-01`, `prod-api-01`, plus `vol-dev-orphan`, `vol-prod-orphan` (unattached) and `vol-prod-data` (in-use).
20. **Wait 75-90 minutes.** The scanner needs an hour of CloudWatch CPU history. While waiting: **EC2 -> select an instance -> Monitoring** and watch `prod-api-01` sit at high CPU while the others stay near zero. Run Part 7 only after the wait.

## Part 7: Rehearse safely (dry-run first)

The stack ships with `DRY_RUN=true`, so nothing is changed yet.

21. **[C]** **Lambda -> `finops-scanner` -> Test tab** -> create an event named `scan` with body `{}` -> **Test**. Read the result summary.
    Or **[T]**:
    ```powershell
    aws lambda invoke --function-name finops-scanner --cli-binary-format raw-in-base64-out --payload '{}' out.json --region ap-south-1
    Get-Content out.json
    aws logs tail /aws/lambda/finops-scanner --since 15m --region ap-south-1
    ```
22. **Expected findings:** `dev-api-01`, `qa-runner-01` and `vol-dev-orphan` -> auto-remediate (simulated); `prod-report-01` and `vol-prod-orphan` -> escalate; `qa-loadtest-02` -> logged only (keep=true); `prod-api-01` and `vol-prod-data` -> not touched. If a finding is missing, wait longer and rerun, and read the log for the reason.

## Part 8: Go live (this is the demo)

23. **[C] Turn off dry-run on BOTH functions:** Lambda -> `finops-scanner` -> **Configuration -> Environment variables -> Edit** -> change `DRY_RUN` from `true` to `false` -> **Save**. Then do exactly the same for **`finops-approver`**. (The approver has its own `DRY_RUN` setting; if it stays `true`, clicking Approve in an email changes nothing and uses up the one-time link.)
24. **[C or T]** Run the scanner again (same Test button or `aws lambda invoke` command).
25. **[C] Check the result** in EC2:
    - `dev-api-01` and `qa-runner-01` -> **Stopped** (automatically, nobody clicked anything).
    - `vol-dev-orphan` is **gone**, and a small snapshot of it exists under **EC2 -> Snapshots** (the project snapshots before deleting).
    - `qa-loadtest-02`, `prod-api-01`, `vol-prod-data` untouched.
    - `prod-report-01` and `vol-prod-orphan` still exist and wait for a human.
26. **[C] Approval email** (only after step 23 is done for both functions): open the AWS Notifications email (check spam) for the escalated prod resources -> click the link -> a confirmation page opens -> click **Approve**. Then refresh EC2: `prod-report-01` is stopped, or `vol-prod-orphan` is deleted. The link works once; reopening it shows an "already used" message.

## Part 9: Show Event History and the encrypted audit trail

27. **[C] Remediation proof in CloudTrail Event History** (no trail needs creating):
    **CloudTrail -> Event history -> Lookup attributes: Event name** -> `StopInstances` (then `DeleteVolume`, `CreateSnapshot`). Click an event to show the instance/volume id and the caller (the scanner or approver Lambda's role). Events can take several minutes to appear.
    Or **[T]**:
    ```powershell
    aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StopInstances --max-results 10 --region ap-south-1
    ```
28. **[C] KMS proof:** Event history -> Lookup attribute **Event source** = `kms.amazonaws.com` -> you will see `GenerateDataKey` calls from the Lambda roles (they can encrypt but not decrypt).
29. **[C] Encrypted audit log:** **DynamoDB -> Tables -> finops-audit-log -> Explore items.** Sensitive fields are unreadable ciphertext.
30. **[T] Decrypt as the auditor role** (the only role allowed to decrypt). Replace the ARN with `AuditorRoleArn` from step 14:
    ```powershell
    $c = aws sts assume-role --role-arn arn:aws:iam::YOUR_ACCOUNT_ID:role/FinOpsAuditorRole --role-session-name auditor-demo | ConvertFrom-Json
    $env:AWS_ACCESS_KEY_ID = $c.Credentials.AccessKeyId
    $env:AWS_SECRET_ACCESS_KEY = $c.Credentials.SecretAccessKey
    $env:AWS_SESSION_TOKEN = $c.Credentials.SessionToken
    $env:AWS_DEFAULT_REGION = "ap-south-1"
    python -m scripts.report
    python scripts/show_decrypted_record.py 3
    ```
    Use `python -m scripts.report` (not `python scripts/report.py`, which fails with "No module named 'src'"). The report decrypts every record and prints a summary; `show_decrypted_record.py` (a separate file that came with this guide, save it in your `scripts` folder) shows a few records as stored ciphertext next to the decrypted fields. Then clear the temporary credentials:
    ```powershell
    Remove-Item Env:AWS_ACCESS_KEY_ID, Env:AWS_SECRET_ACCESS_KEY, Env:AWS_SESSION_TOKEN
    ```
    Back in the console (Event history -> Event source `kms.amazonaws.com`) show the `Decrypt` event made by `FinOpsAuditorRole/auditor-demo`.

**Optional:** `python web/server.py` opens the web console at `http://localhost:8000` with the simulated PixelForge account. It is handy for explaining the policy engine and the decision table, but it is a simulation, not your real account.

## Part 10: Clean up the same day

31. **[T]** Remove demo resources, then wait a couple of minutes:
    ```powershell
    python scripts/teardown.py
    ```
32. **[C] Delete leftover snapshots:** EC2 -> **Snapshots** -> owned by me -> select the ones created by the remediation -> **Actions -> Delete snapshot**.
33. **[T]** Remove the stack and the secret:
    ```powershell
    sam delete --stack-name finops-remediation --region ap-south-1
    aws ssm delete-parameter --name /finops/hmac-secret --region ap-south-1
    ```
    The KMS key is scheduled for deletion (it stops billing while pending).
34. **[C]** IAM -> Users -> `finops-deployer` -> Security credentials -> **delete the access key** (or delete the user). **[T]** run `aws configure` and overwrite the stored keys, or delete `%USERPROFILE%\.aws\credentials`.
35. **[C]** Next day, check **Billing -> Bills** and **EC2** for anything still running.

## If something goes wrong

| Symptom | Likely cause / fix |
|---|---|
| `sam build` fails | Docker Desktop is not running or still starting. |
| `sam deploy` says it requires capabilities | Add `--capabilities CAPABILITY_NAMED_IAM`. |
| Stack fails on `FinOpsAuditorRole` already exists | A previous stack/role with that name exists; delete it, or deploy in a clean account/region. |
| Seed script: no default subnet | EC2/VPC console -> Actions -> **Create default VPC**. |
| Scanner finds nothing | You ran it before ~75-90 minutes passed; or the resources lost their `Project=finops-demo` tag. |
| No approval email | Subscription not confirmed (step 15), check spam, or the escalator Lambda errored (read `/aws/lambda/finops-escalator` logs). |
| Approval link fails with an error | The secret was created with `--key-id` (redo step 16 without it), or the secret does not exist yet. |
| `AccessDenied` in a Lambda log | This is the first real-IAM run; send me the exact message and the function name. |
| Resource stopped when you did not expect it | Check its tags (`env`, `keep`, `Project`) and the scanner log line for its decision. |

## What to tell your professor (honest limits)

- Savings figures are projections from a per-resource price table; the real measurements are detection-to-action time, auto-vs-escalated split and zero false positives on the control resources.
- Prod resources and anything tagged `keep=true` are never auto-remediated; prod needs a human approval.
- One KMS customer-managed key costs about $1/month; EBS snapshots taken before deleting volumes also cost a little until removed.
- The detection window is shortened in demo mode (about 60 minutes for instances); production defaults are 7 days (instances) and 30 days (volumes).
