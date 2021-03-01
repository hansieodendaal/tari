Feature: Stress Test

@long-running
Scenario Outline: Stress Test
    Given I have a seed node NODE1
    And I have a seed node NODE2
    And I have <NumNodes> base nodes connected to all seed nodes
    And I have stress-test wallet WALLET_A connected to the seed node NODE1 with broadcast monitoring timeout 60
    And I have stress-test wallet WALLET_B connected to the seed node NODE2 with broadcast monitoring timeout 60
    And I have a merge mining proxy PROXY connected to NODE1 and WALLET_A
        # We need to ensure the coinbase lock heights are reached; mine enough blocks
        # A single coin split can produce at most 499 outputs
    When I sync merge mine <NumCoinsplitsNeeded> blocks via PROXY
    When I sync mine <NumConfirmations> blocks on NODE1
    Then wallet WALLET_A detects at least <NumCoinsplitsNeeded> coinbase transactions as Mined_Confirmed
    Then I coin split tari in wallet WALLET_A to produce <NumTransactions> UTXOs of 7000 uT each with fee_per_gram 20 uT
    Then wallet WALLET_A detects all transactions are at least Broadcast
        # Make sure enough blocks are mined for the coin split transactions to be confirmed
    When I sync mine <NumBlocksToMine> blocks on NODE1
    When I sync mine <NumConfirmations> blocks on NODE1
    Then wallet WALLET_A detects all transactions as Mined_Confirmed
    When I send <NumTransactions> transactions of 1111 uT each from wallet WALLET_A to wallet WALLET_B at fee_per_gram 20
    When I wait 1 seconds
        # Mine enough blocks for all transactions to be confirmed, ~649 transactions per block
    When I sync mine <NumBlocksToMine> blocks on NODE1
    When I sync mine <NumConfirmations> blocks on NODE1
    Then all wallets detect all transactions as Mined_Confirmed
    When I wait 1 seconds
    Examples:
        | NumTransactions   | NumCoinsplitsNeeded   | NumNodes  | NumBlocksToMine | NumConfirmations |
        | 10                | 1                     | 3         | 1               | 3                |
        | 100               | 1                     | 3         | 1               | 3                |
        | 1000              | 3                     | 3         | 2               | 3                |
        | 10000             | 21                    | 3         | 20              | 3                |
