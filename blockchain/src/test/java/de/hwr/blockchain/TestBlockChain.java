package de.hwr.blockchain;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TestBlockChain {

    private static final Logger LOGGER = Logger.getLogger("TextBlockChain");
    private static final List<Block> BLOCK_CHAIN = new ArrayList<>();
    private static final int PREFIX = 4;

    private final String prefixString = new String(new char[PREFIX]).replace('\0', '0');

    @Test
    void givenBlockchain_whenNewBlockAdded_thenSuccess() {
        addSomeBlocksToChain();
        Block newBlock = new Block(
                "This is a New Block.",
                BLOCK_CHAIN.get(BLOCK_CHAIN.size() - 1).getHash(),
                new Date().getTime());
        newBlock.mineBlock(PREFIX);
        assertEquals(newBlock.getHash().substring(0, PREFIX), prefixString, "FAILURE! Der neue Block konnte nicht zur bestehenden Blockchain hinzugefügt werden.");
        BLOCK_CHAIN.add(newBlock);
        LOGGER.info("Der neue Block konnte zur bestehenden Blockchain hinzugefügt werden.");
    }

    @Test
    void givenBlockchain_whenValidated_thenSuccess() {
        boolean flag = true;
        for (int i = 0; i < BLOCK_CHAIN.size(); i++) {
            String previousHash = i==0 ? "0" : BLOCK_CHAIN.get(i - 1).getHash();
            flag = BLOCK_CHAIN.get(i).getHash().equals(BLOCK_CHAIN.get(i).calculateBlockHash())
                    && previousHash.equals(BLOCK_CHAIN.get(i).getPreviousHash())
                    && BLOCK_CHAIN.get(i).getHash().substring(0, PREFIX).equals(prefixString);
            if (!flag) break;
        }
        assertTrue(flag, "FAILURE! Die vorhandene Blockchain ist nicht valide.");
        LOGGER.info("Die vorhandene Blockchain ist valide.");
    }

    void addSomeBlocksToChain() {
        Block block1 = new Block(
                "First Block.",
                "0",
                new Date().getTime());
        block1.mineBlock(PREFIX);
        BLOCK_CHAIN.add(block1);

        Block block2 = new Block(
                "Second Block.",
                BLOCK_CHAIN.get(BLOCK_CHAIN.size() - 1).getHash(),
                new Date().getTime());
        block2.mineBlock(PREFIX);
        BLOCK_CHAIN.add(block2);
    }
}
