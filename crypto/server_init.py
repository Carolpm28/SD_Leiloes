#Script de teste para verificar startup do servidor
#Executa testes locais sem iniciar o Flask

import sys
import os
import sqlite3

# Assumindo estrutura de pastas
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from crypto.server_exp import init_db, init_auction_ca, init_blind_signature_keys
from crypto.blind_signature import BlindSignature


def test_database():
    """Testa criação da base de dados"""
    print("\n" + "=" * 60)
    print("TEST 1: Database Initialization")
    print("=" * 60)
    
    try:
        # Limpar BD anterior (se existir)
        if os.path.exists('server.db'):
            os.remove('server.db')
            print("  • Removed old database")
        
        # Criar nova
        init_db()
        
        # Verificar tabelas
        conn = sqlite3.connect('server.db')
        c = conn.cursor()
        
        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in c.fetchall()]
        
        expected_tables = [
            'users',
            'anonymous_tokens',
            'ca_certs',
            'auctions',
            'bids',
            'auction_sellers',
            'bid_bidders'
        ]
        
        print(f"\n   Tables created: {len(tables)}")
        for table in tables:
            check = "✓" if table in expected_tables else "✗"
            print(f"    {check} {table}")
        
        conn.close()
        
        if set(tables) == set(expected_tables):
            print("\n   Database test PASSED")
            return True
        else:
            print("\n   Database test FAILED - Missing tables")
            return False
            
    except Exception as e:
        print(f"\n   Database test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_ca():
    """Testa inicialização da CA"""
    print("\n" + "=" * 60)
    print("TEST 2: Certificate Authority")
    print("=" * 60)
    
    try:
        # Primeira inicialização (criar CA)
        print("\n  • First initialization (creating CA)...")
        ca1 = init_auction_ca()
        
        if ca1 is None:
            print("   CA initialization returned None")
            return False
        
        # Verificar se foi guardado na BD
        conn = sqlite3.connect('server.db')
        c = conn.cursor()
        c.execute('SELECT ca_cert_pem, ca_priv_key_pem FROM ca_certs WHERE id=1')
        row = c.fetchone()
        conn.close()
        
        if not row:
            print("   CA not saved to database")
            return False

        print("   CA created and saved")

        # Segunda inicialização (carregar CA)
        print("\n  • Second initialization (loading CA)...")
        ca2 = init_auction_ca()
        
        if ca2 is None:
            print("   CA loading returned None")
            return False
        
        # Verificar se é a mesma CA
        cert1_bytes = ca1.ca_cert.public_bytes(serialization.Encoding.PEM)
        cert2_bytes = ca2.ca_cert.public_bytes(serialization.Encoding.PEM)
        
        if cert1_bytes == cert2_bytes:
            print("   CA loaded correctly (same certificate)")
            print("\n   CA test PASSED")
            return True
        else:
            print("   CA mismatch - different certificates")
            return False
            
    except Exception as e:
        print(f"\n   CA test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_server_keys():
    """Testa inicialização das chaves do servidor"""
    print("\n" + "=" * 60)
    print("TEST 3: Server Keys (Blind Signatures)")
    print("=" * 60)
    
    try:
        # Limpar ficheiros anteriores
        for f in ['server_private.pem', 'server_public.pem']:
            if os.path.exists(f):
                os.remove(f)
                print(f"  • Removed old {f}")
        
        # Primeira inicialização (gerar chaves)
        print("\n  • First initialization (generating keys)...")
        priv1, pub1 = init_server_keys()
        
        if not os.path.exists('server_private.pem') or not os.path.exists('server_public.pem'):
            print("   Key files not created")
            return False
        
        print("   Keys generated and saved")
        
        # Segunda inicialização (carregar chaves)
        print("\n  • Second initialization (loading keys)...")
        priv2, pub2 = init_server_keys()
        
        # Verificar se são as mesmas chaves
        from cryptography.hazmat.primitives import serialization
        
        pub1_bytes = pub1.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub2_bytes = pub2.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        if pub1_bytes == pub2_bytes:
            print("   Keys loaded correctly (same keys)")
            print("\n   Server keys test PASSED")
            return True
        else:
            print("   Key mismatch - different keys")
            return False
            
    except Exception as e:
        print(f"\n   Server keys test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_blind_signatures():
    """Testa sistema de blind signatures"""
    print("\n" + "=" * 60)
    print("TEST 4: Blind Signatures")
    print("=" * 60)
    
    try:
        # Obter chaves do servidor
        priv_key, pub_key = init_server_keys()
        
        # Criar handler
        bs = BlindSignature()
        
        # Testar blind signature flow
        print("\n  • Testing blind signature protocol...")
        
        message = "TEST_TOKEN_123"
        
        # Cliente: blind
        blinded_msg, r, msg_hash = bs.blind(message, pub_key)
        print("   Message blinded")
        
        # Servidor: sign
        blinded_sig = bs.blind_sign(blinded_msg, priv_key)
        print("   Blinded message signed")
        
        # Cliente: unblind
        signature = bs.unblind(blinded_sig, r, pub_key)
        print("   Signature unblinded")
        
        # Verificar
        valid = bs.verify(message, signature, pub_key)
        
        if valid:
            print("   Signature verified successfully")
            print("\n   Blind signatures test PASSED")
            return True
        else:
            print("   Signature verification failed")
            return False
            
    except Exception as e:
        print(f"\n   Blind signatures test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_timestamp_service():
    """Testa serviço de timestamps"""
    print("\n" + "=" * 60)
    print("TEST 5: Timestamp Service")
    print("=" * 60)
    
    try:
        from crypto.timestamp_service import TimestampService
        
        # Inicializar serviço
        tsa = TimestampService(db_path='server.db')
        print("   TimestampService initialized")
        
        # Emitir timestamp
        item_hash = "TEST_ITEM_HASH_123"
        ts = tsa.issue_timestamp(item_hash)
        print("   Timestamp issued")
        
        # Verificar campos
        if ts['payload']['item'] == item_hash:
            print("  Timestamp payload verified")
            print("\n  Timestamp service test PASSED")
            return True
        else:
            print("  Timestamp payload mismatch")
            return False
            
    except Exception as e:
        print(f"\n  Timestamp service test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_all_tests():
    """Executa todos os testes"""
    print("\n" + "=" * 60)
    print("AUCTION SERVER - STARTUP TESTS")
    print("=" * 60)
    
    results = []
    
    # Test 1: Database
    results.append(("Database", test_database()))
    
    # Test 2: CA
    results.append(("Certificate Authority", test_ca()))
    
    # Test 3: Server Keys
    results.append(("Server Keys", test_server_keys()))
    
    # Test 4: Blind Signatures
    results.append(("Blind Signatures", test_blind_signatures()))
    
    # Test 5: Timestamp Service
    results.append(("Timestamp Service", test_timestamp_service()))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"  {status} - {name}")
    
    print("\n" + "=" * 60)
    print(f"Result: {passed}/{total} tests passed")
    print("=" * 60 + "\n")
    
    return passed == total


if __name__ == '__main__':
    from cryptography.hazmat.primitives import serialization
    
    success = run_all_tests()
    
    if success:
        print("All tests passed! Server is ready to run.")
        print("\nYou can now start the server with:")
        print("  python server/main.py")
        sys.exit(0)
    else:
        print("Some tests failed. Please fix issues before running server.")
        sys.exit(1)