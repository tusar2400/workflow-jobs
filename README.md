# WorkFlow Jobs — Render Ready

Included features:
- Gunicorn production start command
- Password hashing with Werkzeug
- SQLite database with Render persistent disk configuration
- Site-entry math captcha + login/register captcha
- Worker balance, earnings and transaction ledger
- Deposit requests (bKash, Nagad, Bank, PayPal) with admin approval and automatic balance credit
- Withdrawal requests with balance hold and automatic refund on rejection
- Job applications and proof submission
- Admin approval/rejection of submitted work; approved rewards are automatically credited
- Admin job creation
- CSRF tokens and safer session cookies

## Render
1. Upload this ZIP to your repository.
2. Create the Web Service from the repository.
3. Set `ADMIN_EMAIL` to the email of the account you will use as admin.
4. Keep `SECRET_KEY` as a generated Render secret.
5. The included `render.yaml` uses `/var/data/workflow_jobs.db` on a persistent disk.

### Important
The deposit page is a **manual payment-verification flow**, not an automatic payment gateway. Users submit their payment details/reference, and the admin approves the request. Real automatic bKash/Nagad/PayPal payment processing requires the corresponding merchant/API credentials and gateway integration.
