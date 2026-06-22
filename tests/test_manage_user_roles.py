import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from gestor_inventory.application.manage_user_roles import (
    AssignUserRoleRequest,
    RevokeUserRoleRequest,
    assign_user_role,
    revoke_user_role,
)
from gestor_inventory.domain.errors import ForbiddenError
from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository


class ManageUserRolesTests(unittest.TestCase):
    def setUp(self):
        self.repo = SqliteUserRepository(":memory:")
        self.admin, _ = self.repo.create_user_with_role(
            company_id=1, email="admin@example.com", password_hash="hash", role_id=12
        )
        self.superadmin, _ = self.repo.create_user_with_role(
            company_id=1, email="superadmin@example.com", password_hash="hash", role_id=13
        )
        self.target, _ = self.repo.create_user_with_role(
            company_id=1, email="target@example.com", password_hash="hash", role_id=10
        )

    def test_admin_cannot_assign_superadmin(self):
        with self.assertRaises(ForbiddenError):
            assign_user_role(
                self.repo,
                AssignUserRoleRequest(
                    company_id=1,
                    actor_user_id=self.admin.id,
                    user_id=self.target.id,
                    role_id=13,
                ),
            )

    def test_admin_cannot_modify_superadmin_roles(self):
        with self.assertRaises(ForbiddenError):
            revoke_user_role(
                self.repo,
                RevokeUserRoleRequest(
                    company_id=1,
                    actor_user_id=self.admin.id,
                    user_id=self.superadmin.id,
                    role_id=13,
                ),
            )

    def test_admin_cannot_modify_own_roles(self):
        with self.assertRaises(ForbiddenError):
            assign_user_role(
                self.repo,
                AssignUserRoleRequest(
                    company_id=1,
                    actor_user_id=self.admin.id,
                    user_id=self.admin.id,
                    role_id=13,
                ),
            )

    def test_superadmin_can_assign_and_revoke_superadmin(self):
        res_assign = assign_user_role(
            self.repo,
            AssignUserRoleRequest(
                company_id=1,
                actor_user_id=self.superadmin.id,
                user_id=self.target.id,
                role_id=13,
            ),
        )
        self.assertTrue(res_assign.changed)
        self.assertIn("Superadministrador", set(self.repo.list_user_role_names(company_id=1, user_id=self.target.id)))

        res_revoke = revoke_user_role(
            self.repo,
            RevokeUserRoleRequest(
                company_id=1,
                actor_user_id=self.superadmin.id,
                user_id=self.target.id,
                role_id=13,
            ),
        )
        self.assertTrue(res_revoke.changed)
        self.assertNotIn("Superadministrador", set(self.repo.list_user_role_names(company_id=1, user_id=self.target.id)))


if __name__ == "__main__":
    unittest.main()
