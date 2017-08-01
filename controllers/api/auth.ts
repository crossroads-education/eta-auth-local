import * as eta from "../../eta";
import * as db from "../../db";

@eta.mvc.route("/api/auth/local")
@eta.mvc.controller()
export default class ApiAuthLocalController extends eta.IHttpController {
    @eta.mvc.raw()
    @eta.mvc.post()
    @eta.mvc.params(["username", "password"])
    public async login(username: string, password: string): Promise<void> {
        const account: db.Account = await db.account().createQueryBuilder("account")
            .leftJoinAndSelect("account.person", "person")
            .where("person.username = :username", { username })
            .getOne();
        if (!account) {
            this.redirect("/auth/local/login?error=Invalid%20login");
            return;
        }
        const hashed: string = eta.crypto.hashPassword(password, account.salt);
        if (hashed !== account.password) {
            this.redirect("/auth/local/login?error=Invalid%20login");
            return;
        }
        this.req.session.userid = account.person.id;
        await this.saveSession();
        this.redirect(this.req.session.authFrom);
    }

    @eta.mvc.raw()
    @eta.mvc.get()
    public async logout(): Promise<void> {
        this.req.session.userid = undefined;
        await this.saveSession();
        this.redirect(this.req.session.authFrom);
    }

    @eta.mvc.raw()
    @eta.mvc.post()
    @eta.mvc.params(["firstName", "lastName", "username", "email", "password"])
    public async register(
        firstName: string, lastName: string,
        username: string, email: string,
        password: string): Promise<void> {
        const person: db.Person = new db.Person({
            firstName,
            lastName,
            username,
            email
        });
        await db.person().save(person);
        const salt: string = eta.crypto.generateSalt();
        const hashed: string = eta.crypto.hashPassword(password, salt);
        const account: db.Account = new db.Account({
            password: hashed,
            salt,
            person
        });
        await db.account().save(account);
        this.redirect("/auth/local/login?success=Successfully%20registered.");
    }

    @eta.mvc.raw()
    @eta.mvc.post()
    @eta.mvc.authorize()
    @eta.mvc.params(["oldPassword", "newPassword"])
    public async changePassword(oldPassword: string, newPassword: string): Promise<void> {
        const account: db.Account = await db.account().createQueryBuilder("account")
            .leftJoinAndSelect("account.person", "person")
            .where(`"person"."id" = :id`, { id: this.req.session.userid })
            .getOne();
        if (!account) {
            return this.redirect("/auth/local/changePassword?error=Something%20went%20wrong.");
        }
        const hashed: string = eta.crypto.hashPassword(oldPassword, account.salt);
        if (hashed !== account.password) {
            return this.redirect("/auth/local/changePassword?error=Password%20incorrect.");
        }
        account.salt = eta.crypto.generateSalt();
        account.password = eta.crypto.hashPassword(newPassword, account.salt);
        await db.account().save(account);
        this.redirect("/auth/local/login?success=Successfully%20changed%20password.");
    }
}
