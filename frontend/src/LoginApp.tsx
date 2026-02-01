export function LoginApp() {
	return (
		<main className="container login-container">
			<article>
				<header>
					<h1>Admin Login</h1>
				</header>
				<p>Select an OAuth provider to sign in:</p>
				<div className="oauth-buttons">
					<a href="/auth/google" role="button" className="oauth-btn">
						Sign in with Google
					</a>
				</div>
			</article>
			<p>
				<a href="/">Back to Home</a>
			</p>
		</main>
	);
}
