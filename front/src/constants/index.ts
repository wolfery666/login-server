export const LOGIN_MAX_LENGTH = 20

export const PASSWORD_MIN_LENGTH = 6
export const PASSWORD_MAX_LENGTH = 20

export const LOGIN_RULES = [
    (v: string) => !!v || 'Login is required',
    (v: string) => v.length <= LOGIN_MAX_LENGTH || `Max ${LOGIN_MAX_LENGTH} characters`,
    (v: string) => /^[A-Za-z][_A-Za-z0-9]*$/.test(v) || `Login should start with letter and may contain letters, digits and underscores`,
  ]

export const PASSWORD_RULES = [
    (v: string) => v.length >= PASSWORD_MIN_LENGTH || `Min ${PASSWORD_MIN_LENGTH} characters`,
    (v: string) => v.length <= PASSWORD_MAX_LENGTH || `Max ${PASSWORD_MAX_LENGTH} characters`,
  ]
