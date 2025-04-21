import streamlit as st

# ✅ Must be first Streamlit command
st.set_page_config(page_title="Money Laundering Detection", layout="wide")

import pandas as pd
import hashlib
import time
import plotly.express as px
from collections import defaultdict, Counter

# ---------------------- Transaction Definition ----------------------
class Transaction:
    def __init__(self, sender, receiver, amount, currency, is_laundering, payment_type):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.currency = currency
        self.is_laundering = bool(is_laundering)
        self.payment_type = payment_type

    def __str__(self):
        status = "🚨 Suspicious" if self.is_laundering else "✅ Normal"
        return f"{self.sender} → {self.receiver} | {self.amount} {self.currency} | {self.payment_type} | {status}"

# ---------------------- Block & Blockchain Ledger ----------------------
class Block:
    def __init__(self, index, transactions, previous_hash):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        txn_str = "".join(str(txn) for txn in self.transactions)
        block_string = f"{self.index}{self.timestamp}{txn_str}{self.previous_hash}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def __str__(self):
        return f"Block #{self.index} | Hash: {self.hash[:10]}... | Prev: {self.previous_hash[:10]}..."

class BlockchainLedger:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.all_transactions = []

    def create_genesis_block(self):
        return Block(0, [], "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, transactions):
        index = len(self.chain)
        prev_hash = self.get_latest_block().hash
        new_block = Block(index, transactions, prev_hash)
        self.chain.append(new_block)
        self.all_transactions.extend(transactions)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            curr, prev = self.chain[i], self.chain[i-1]
            if curr.hash != curr.calculate_hash() or curr.previous_hash != prev.hash:
                return False
        return True

    def search_by_account(self, account_id):
        return [txn for txn in self.all_transactions if txn.sender == account_id or txn.receiver == account_id]

    def filter_by_laundering(self, status=True):
        return [txn for txn in self.all_transactions if txn.is_laundering == status]

    def sort_by_amount(self, descending=True):
        return sorted(self.all_transactions, key=lambda txn: txn.amount, reverse=descending)

    def summary(self):
        laundering = sum(txn.is_laundering for txn in self.all_transactions)
        total = len(self.all_transactions)
        return {
            "Total Transactions": total,
            "Suspicious": laundering,
            "Normal": total - laundering,
            "Total Blocks": len(self.chain)
        }

# ---------------------- Helper Functions ----------------------
@st.cache_data(show_spinner="📄 Reading file...")
def load_dataframe(uploaded_file):
    return pd.read_csv(uploaded_file, on_bad_lines='skip')

@st.cache_data(show_spinner="🔧 Processing transactions...")
def process_transactions(df, block_size=100):
    ledger = BlockchainLedger()
    txn_batch = []
    for i, (_, row) in enumerate(df.iterrows(), 1):
        try:
            txn = Transaction(
                sender=row['Sender_account'],
                receiver=row['Receiver_account'],
                amount=float(row['Amount']),
                currency=row['Payment_currency'],
                is_laundering=int(row['Is_laundering']),
                payment_type=row['Payment_type']
            )
            txn_batch.append(txn)
            if len(txn_batch) >= block_size:
                ledger.add_block(txn_batch)
                txn_batch = []
        except Exception:
            continue
    if txn_batch:
        ledger.add_block(txn_batch)
    return ledger

# ---------------------- Streamlit UI ----------------------
st.title("💸 Money Laundering Detection - Blockchain Ledger")

uploaded_file = st.file_uploader("Upload Transaction CSV", type=["csv"])

if uploaded_file is not None:
    progress_bar = st.progress(0, text="🔄 Starting...")

    try:
        progress_bar.progress(10, text="📄 Loading CSV...")
        df = load_dataframe(uploaded_file)

        st.subheader("🔍 Preview of Data")
        st.dataframe(df.head(10))

        max_rows = st.slider("Limit number of transactions to process", 100, min(10000, len(df)), 1000, step=100)
        df = df.head(max_rows)

        progress_bar.progress(30, text="⛓️ Processing Blockchain...")
        with st.spinner("Processing transactions..."):
            ledger = process_transactions(df)

        progress_bar.progress(75, text="✅ Blockchain Created")
        st.success(f"✅ Blockchain built with {len(ledger.chain)} blocks.")

        summary = ledger.summary()

        # Summary Display
        st.subheader("📊 Summary")
        st.json(summary)

        # Graph 1: Transaction Type Pie
        pie_fig = px.pie(
            names=["Normal", "Suspicious"],
            values=[summary["Normal"], summary["Suspicious"]],
            title="🧮 Transaction Status Distribution",
            color_discrete_sequence=["green", "red"]
        )
        st.plotly_chart(pie_fig, use_container_width=True)

        # Graph 2: Top Accounts
        account_volume = defaultdict(float)
        for txn in ledger.all_transactions:
            account_volume[txn.sender] += txn.amount
            account_volume[txn.receiver] += txn.amount
        top_accounts = Counter(account_volume).most_common(10)
        if top_accounts:
            accounts, volumes = zip(*top_accounts)
            bar_fig = px.bar(
                x=accounts, y=volumes,
                labels={"x": "Account ID", "y": "Transaction Volume"},
                title="💼 Top 10 Accounts by Transaction Volume",
                color=volumes,
                color_continuous_scale="blues"
            )
            st.plotly_chart(bar_fig, use_container_width=True)

        # Blockchain validation (on-demand)
        st.subheader("🔒 Blockchain Integrity")
        if st.button("Run Validation"):
            progress_bar.progress(90, text="🔒 Validating Blockchain...")
            if ledger.is_chain_valid():
                st.success("✅ Blockchain is valid.")
            else:
                st.error("❌ Blockchain is invalid!")

        # Search by Account
        st.subheader("🔍 Search by Account")
        account = st.text_input("Enter Account ID:")
        if account:
            try:
                account_id = int(account)
                results = ledger.search_by_account(account_id)
                for txn in results[:10]:
                    st.text(str(txn))
            except ValueError:
                st.warning("Invalid account ID.")

        # Suspicious (on-demand)
        if st.checkbox("Show Suspicious Transactions"):
            st.subheader("⚠️ Suspicious Transactions")
            for txn in ledger.filter_by_laundering(True)[:5]:
                st.text(str(txn))

        # Top 5 by amount (on-demand)
        if st.checkbox("Show Top 5 Transactions by Amount"):
            st.subheader("💰 Top 5 Transactions by Amount")
            for txn in ledger.sort_by_amount()[:5]:
                st.text(str(txn))

        # Blockchain Explorer (on-demand)
        st.subheader("🧱 Blockchain Explorer")
        if st.checkbox("Show Blockchain Explorer"):
            for block in ledger.chain:
                with st.expander(f"{str(block)}"):
                    for txn in block.transactions[:10]:
                        st.text(str(txn))

        progress_bar.progress(100, text="✅ Done")

    except Exception as e:
        progress_bar.empty()
        st.error(f"❌ Error: {e}")
