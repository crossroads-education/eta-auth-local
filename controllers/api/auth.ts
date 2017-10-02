import * as eta from "../../eta";
import * as db from "../../db";

@eta.mvc.route("/api/auth/local")
@eta.mvc.controller()
export default class ApiAuthLocalController extends eta.IHttpController {
    @eta.mvc.raw()
    @eta.mvc.post()
    public async login({ username, password }: { username: string, password: string }): Promise<void> {
        const account: db.Account = await db.account().createQueryBuilder("account")
            .leftJoinAndSelect("account.user", "user")
            .where("user.username = :username", { username })
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
        this.req.session.userid = account.user.id;
        if (!this.req.session.authFrom) this.req.session.authFrom = "/home/index";
        await this.saveSession();
        this.redirect(this.req.session.authFrom);
    }

    @eta.mvc.raw()
    @eta.mvc.get()
    public async logout(): Promise<void> {
        this.req.session.userid = undefined;
        if (!this.req.session.authFrom) this.req.session.authFrom = "/home/index";
        await this.saveSession();
        this.redirect(this.req.session.authFrom);
    }

    @eta.mvc.raw()
    @eta.mvc.post()
    public async register(params: Partial<db.User> & { password: string }): Promise<void> {
        const user: db.User = db.user().create(params);
        await db.user().save(user);
        const salt: string = eta.crypto.generateSalt();
        const hashed: string = eta.crypto.hashPassword(params.password, salt);
        await db.account().save(db.account().create({
            password: hashed,
            salt,
            user
        }));
        this.redirect("/auth/local/login?success=Successfully%20registered.");
    }

    @eta.mvc.raw()
    @eta.mvc.post()
    @eta.mvc.authorize()
    public async changePassword({ oldPassword, newPassword }: { oldPassword: string, newPassword: string }): Promise<void> {
        const account: db.Account = await db.account().createQueryBuilder("account")
            .where(`"account"."userId" = :userId`, { userId: this.req.session.userid })
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
