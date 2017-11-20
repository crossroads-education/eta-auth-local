import * as eta from "../../eta";

@eta.mvc.route("/auth/local")
@eta.mvc.controller()
export default class AuthLocalController extends eta.IHttpController {
    private global(): void {
        this.res.view["success"] = this.req.query.success;
        this.res.view["error"] = this.req.query.error;
    }

    @eta.mvc.get()
    public async login(): Promise<void> {
        if (this.isLoggedIn()) {
            eta.logger.trace(this.req.session.authFrom);
            this.redirect(this.req.session.authFrom);
            return;
        }
        this.global();
    }

    @eta.mvc.raw()
    @eta.mvc.get()
    public async logout(): Promise<void> {
        this.redirect("/api/auth/local/logout");
    }

    @eta.mvc.get()
    public async register(): Promise<void> {
        this.global();
    }

    @eta.mvc.authorize()
    @eta.mvc.get()
    public async changePassword(): Promise<void> {
        this.global();
    }
}
