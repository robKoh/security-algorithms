package com.hwr.blockchain;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TestBlockChain {

    List<Block> blockchain = new ArrayList<>();
    int prefix = 4;
    String prefixString = new String(new char[prefix]).replace('\0', '0');

    @Test
    void givenBlockchain_whenNewBlockAdded_thenSuccess() {
        addSomeBlocksToChain();
        Block newBlock = new Block(
                "This is a New Block.",
                blockchain.get(blockchain.size() - 1).getHash(),
                new Date().getTime());
        newBlock.mineBlock(prefix);
        assertEquals(newBlock.getHash().substring(0, prefix), prefixString);
        blockchain.add(newBlock);
    }

    @Test
    void givenBlockchain_whenValidated_thenSuccess() {
        boolean flag = true;
        for (int i = 0; i < blockchain.size(); i++) {
            String previousHash = i==0 ? "0" : blockchain.get(i - 1).getHash();
            flag = blockchain.get(i).getHash().equals(blockchain.get(i).calculateBlockHash())
                    && previousHash.equals(blockchain.get(i).getPreviousHash())
                    && blockchain.get(i).getHash().substring(0, prefix).equals(prefixString);
            if (!flag) break;
        }
        assertTrue(flag);
    }

    void addSomeBlocksToChain() {
        blockchain.add(new Block(
                "First Block.",
                "0",
                new Date().getTime()));
        blockchain.add(new Block(
            "Second Block.",
            blockchain.get(blockchain.size() - 1).getHash(),
            new Date().getTime()));
    }
}
