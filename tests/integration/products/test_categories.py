import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from gestor_inventory.application.categories import CreateCategoryRequest, create_category
from gestor_inventory.domain.errors import ValidationError
from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository
from gestor_inventory.security.password_hash import hash_password


class CategoriesIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.repo = SqliteUserRepository(":memory:")
        password_hash_v = hash_password("Strong1!")
        self.user_a, _ = self.repo.create_user_with_role(
            company_id=1, email="admin-a@example.com", password_hash=password_hash_v, role_id=12
        )
        self.user_b, _ = self.repo.create_user_with_role(
            company_id=2, email="admin-b@example.com", password_hash=password_hash_v, role_id=12
        )

    def test_create_category_success_within_tenant(self):
        res = create_category(self.repo, CreateCategoryRequest(company_id=1, name="Bebidas"))
        self.assertEqual(res.category.company_id, 1)
        self.assertEqual(res.category.name, "Bebidas")
        self.assertEqual(res.category.status, "active")
        self.assertTrue(res.category.is_active)

        rows = self.repo.list_categories(company_id=1, status=None)
        self.assertTrue(any(c.id == res.category.id for c in rows))
        self.assertTrue(all(c.company_id == 1 for c in rows))

    def test_duplicate_name_same_tenant_rejected(self):
        create_category(self.repo, CreateCategoryRequest(company_id=1, name="Lácteos"))
        with self.assertRaises(ValidationError):
            create_category(self.repo, CreateCategoryRequest(company_id=1, name="Lácteos"))

        created_b = create_category(self.repo, CreateCategoryRequest(company_id=2, name="Lácteos")).category
        self.assertEqual(created_b.company_id, 2)

    def test_isolation_tenant_a_cannot_see_tenant_b_categories(self):
        cat_a = create_category(self.repo, CreateCategoryRequest(company_id=1, name="Snacks")).category
        cat_b = create_category(self.repo, CreateCategoryRequest(company_id=2, name="Electrónica")).category

        list_a = self.repo.list_categories(company_id=1, status=None)
        ids_a = {c.id for c in list_a}
        self.assertIn(cat_a.id, ids_a)
        self.assertNotIn(cat_b.id, ids_a)
        self.assertTrue(all(c.company_id == 1 for c in list_a))


if __name__ == "__main__":
    unittest.main()
