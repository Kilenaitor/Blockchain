import java.security.interfaces.*;
import java.security.interfaces.RSAKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class TxHandler {

	static UTXOPool pool;

	/* Creates a public ledger whose current UTXOPool (collection of unspent 
	 * transaction outputs) is utxoPool. This should make a defensive copy of 
	 * utxoPool by using the UTXOPool(UTXOPool uPool) constructor.
	 */
	public TxHandler(UTXOPool utxoPool) {
		pool = new UTXOPool(utxoPool);
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
            if(pool.getTxOutput(utxo) != null) {
                Transaction.Output out = pool.getTxOutput(utxo);
                if(!out.address.verifySignature(tx.getRawDataToSign(i), in.signature)) {
                    return false;
                }
            }
        }

        // 3
        List<UTXO> trans = new ArrayList<>();
        for(int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input in = tx.getInput(i);
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
            trans.add(utxo);
        }

        trans = trans.parallelStream().distinct().collect(Collectors.toList());
        if(trans.size() < tx.numInputs()) {
            return false;
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
            if(pool.getTxOutput(utxo) != null) {
                inTotal += pool.getTxOutput(utxo).value;
            }
        }

        return inTotal >= outTotal;
	}

	/* Handles each epoch by receiving an unordered array of proposed 
	 * transactions, checking each transaction for correctness, 
	 * returning a mutually valid array of accepted transactions, 
	 * and updating the current UTXO pool as appropriate.
	 */
	public Transaction[] handleTxs(Transaction[] possibleTxs) {
		// IMPLEMENT THIS
		return possibleTxs;
	}

} 