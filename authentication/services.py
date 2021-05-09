"""Functions, that take care of writing things to the Dynamics database."""


__all__ = [
    "create_account",
    "delete_account",
]


def create_account(firstname: str, lastname: str, email: str, phone: str):
    pass

    # TODO: Create new account for non-dynamics people.
    # Can't allow linking to business here!
    # Make new accoutn entity, that has the customer relationship
    # -> This should make new contact automatically


def delete_account(firstname: str, lastname: str, email: str, phone: str):
    pass
    # TODO: Delete account for non dynamics people
