import java.security.interfaces.*;
import java.security.interfaces.RSAKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class TxHandler {

    private UTXOPool pool;

    /* Creates a public ledger whose current UTXOPool (collection of unspent
     * transaction outputs) is utxoPool. This should make a defensive copy of
     * utxoPool by using the UTXOPool(UTXOPool uPool) constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        pool = new UTXOPool(utxoPool);
    }

    public UTXOPool getUTXOPool() {
        return new UTXOPool(this.pool);
    }

	/* Returns true if
	 * (1) all outputs claimed by tx are in the current UTXO pool,
	 * (2) the signatures on each input of tx are valid,
	 * (3) no UTXO is claimed multiple times by tx,
	 * (4) all of tx’s output values are non-negative, and
	 * (5) the sum of tx’s input values is greater than or equal to the sum of
	        its output values;
	   and false otherwise.
	 */
    public boolean isValidTx(Transaction tx) {
        double outTotal = 0.0;
        double inTotal = 0.0;

        // 1
        for(int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input in = tx.getInput(i);
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
            if(!pool.contains(utxo)) {
                return false;
            }
        }

        // 2
        for(int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input in = tx.getInput(i);
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
            Transaction.Output out = pool.getTxOutput(utxo);
            if(in.signature == null) return false;
            if(!out.address.verifySignature(tx.getRawDataToSign(i), in.signature)) {
                return false;
            }
        }

        // 3
        List<UTXO> trans = new ArrayList<>();
        for(int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input in = tx.getInput(i);
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
            if(trans.contains(utxo)) {
                return false;
            }
            trans.add(utxo);
        }

        // 4
        for(Transaction.Output out : tx.getOutputs()) {
            if(out.value < 0) {
                return false;
            }
            outTotal += out.value;
        }

        // 5
        for(Transaction.Input in : tx.getInputs()) {
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
            inTotal += pool.getTxOutput(utxo).value;
        }

        return inTotal >= outTotal;
    }

    /* Handles each epoch by receiving an unordered array of proposed
     * transactions, checking each transaction for correctness,
     * returning a mutually valid array of accepted transactions,
     * and updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        ArrayList<Transaction> txs = new ArrayList<>();

        for(Transaction tx : possibleTxs) {
            if(isValidTx(tx)) {
                txs.add(tx);
            } else {
                // Skip invalid transactions
                continue;
            }

            // Process valid transactions
            for(Transaction.Input in : tx.getInputs()) {
                UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
                pool.removeUTXO(utxo);
            }
            for(int j = 0; j < tx.getOutputs().size(); j++) {
                UTXO utxo = new UTXO(tx.getHash(), j);
                pool.addUTXO(utxo, tx.getOutput(j));
            }
        }

        // Convert ArrayList back to Array
        Transaction[] validTxs = new Transaction[txs.size()];
        validTxs = txs.toArray(validTxs);

        return validTxs;
    }
}