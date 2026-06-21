import os
import sqlite3
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository


class ProductsIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.repo = SqliteUserRepository(":memory:")

    def test_create_product_success_valid_data(self):
        cat_a = self.repo.create_category(company_id=1, name="Cat A", is_active=True)
        p = self.repo.create_product(company_id=1, category_id=cat_a.id, sku="SKU-1", name="Producto 1", description=None)
        self.assertEqual(p.company_id, 1)
        self.assertEqual(p.category_id, cat_a.id)
        self.assertEqual(p.sku, "SKU-1")
        self.assertEqual(p.stock_minimum, 0)
        self.assertEqual(p.status, "active")

        by_sku = self.repo.get_product_by_sku(company_id=1, sku="SKU-1")
        self.assertIsNotNone(by_sku)
        self.assertEqual(by_sku.id, p.id)

    def test_sku_unique_within_same_company(self):
        cat_a = self.repo.create_category(company_id=1, name="Cat SKU", is_active=True)
        self.repo.create_product(company_id=1, category_id=cat_a.id, sku="DUP-1", name="P1", description=None)
        with self.assertRaises(sqlite3.IntegrityError):
            self.repo.create_product(company_id=1, category_id=cat_a.id, sku="DUP-1", name="P2", description=None)

    def test_same_sku_allowed_across_companies(self):
        cat_a = self.repo.create_category(company_id=1, name="Cat A2", is_active=True)
        cat_b = self.repo.create_category(company_id=2, name="Cat B2", is_active=True)

        p1 = self.repo.create_product(company_id=1, category_id=cat_a.id, sku="SKU-SHARED", name="P1", description=None)
        p2 = self.repo.create_product(company_id=2, category_id=cat_b.id, sku="SKU-SHARED", name="P2", description=None)
        self.assertEqual(p1.company_id, 1)
        self.assertEqual(p2.company_id, 2)

    def test_category_fk_composite_blocks_cross_tenant_category(self):
        cat_a = self.repo.create_category(company_id=1, name="Cat A3", is_active=True)
        cat_b = self.repo.create_category(company_id=2, name="Cat B3", is_active=True)
        self.assertNotEqual(cat_a.id, cat_b.id)

        with self.assertRaises(sqlite3.IntegrityError):
            self.repo.create_product(company_id=1, category_id=cat_b.id, sku="SKU-XT", name="XT", description=None)


if __name__ == "__main__":
    unittest.main()
