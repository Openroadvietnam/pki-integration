package org.jasig.cas.authentication.handler.support;

import javax.sql.DataSource;
import javax.validation.constraints.NotNull;

import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.springframework.jdbc.core.simple.SimpleJdbcTemplate;

public class ETokenAuthenticationHandler extends
		AbstractUsernamePasswordAuthenticationHandler {
	@NotNull
	private SimpleJdbcTemplate jdbcTemplate;
	@NotNull
	private DataSource dataSource;
	@NotNull
	private String sql;

	public final void setDataSource(DataSource dataSource) {
		this.jdbcTemplate = new SimpleJdbcTemplate(dataSource);
		this.dataSource = dataSource;
	}

	protected final SimpleJdbcTemplate getJdbcTemplate() {
		return this.jdbcTemplate;
	}

	protected final DataSource getDataSource() {
		return this.dataSource;
	}

	public void setSql(String sql) {
		this.sql = sql;
	}

	@Override
	protected boolean authenticateUsernamePasswordInternal(
			UsernamePasswordCredentials credentials)
			throws AuthenticationException {
		// Response contains in password field
		String username = credentials.getUsername();
		String token = credentials.getPassword();
		try {
			String tokenResponse = (String) getJdbcTemplate().queryForObject(
					this.sql, String.class, new Object[] { username });
			return tokenResponse.equals(token);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return false;
	}

}
