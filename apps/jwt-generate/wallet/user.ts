import { Ledger, JSON } from "@klave/sdk";
import { emit, revert } from "../klave/types"

const UsersTable = "UsersTable";

@JSON
export class User {
    id: string;
    role: string;   // admin, user, etc.

    constructor(id: string) {
        this.id = id;
        this.role = "";
    }

    static load(userId: string) : User | null {
        let userTable = Ledger.getTable(UsersTable).get(userId);
        if (userTable.length == 0) {
            revert(`User ${userId} does not exists. Create it first`);
            return null;
        }
        let user = JSON.parse<User>(userTable);
        emit(`User loaded successfully: '${user.id}'`);
        return user;
    }

    save(): void {
        let userTable = JSON.stringify<User>(this);
        Ledger.getTable(UsersTable).set(this.id, userTable);
        emit(`User saved successfully: '${this.id}'`);
    }

    delete(): void {
        this.id = "";
        this.role = "";
        Ledger.getTable(UsersTable).unset(this.id);
        emit(`User deleted successfully: '${this.id}'`);
    }
}
