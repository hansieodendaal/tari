Feature: Wallet Transfer

  Scenario: As a wallet I want to submit multiple transfers
    Given I have a seed node NODE
        # Add a 2nd node otherwise initial sync will not succeed
    And I have 1 base nodes connected to all seed nodes
    And I have wallet Wallet_A connected to all seed nodes
    And I have a merge mining proxy PROXY connected to NODE and Wallet_A
    And I have wallet Wallet_B connected to all seed nodes
    And I have wallet Wallet_C connected to all seed nodes
    When I merge mine 10 blocks via PROXY
    Then all nodes are at height 10
    When I send 50000 uT from Wallet_A to Wallet_B and Wallet_C at fee 100
    And I merge mine 10 blocks via PROXY
    Then all nodes are at height 20
    Then all wallets detect all transactions as Mined_Confirmed

