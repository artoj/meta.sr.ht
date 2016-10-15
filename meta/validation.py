from markupsafe import Markup

class ValidationError:
    def __init__(self, field, message):
        self.field = field
        self.message = message

class Validation:
    def __init__(self, request):
        self.request = request
        self.errors = []

    @property
    def ok(self):
        return len(self.errors) == 0

    def cls(self, name):
        return 'has-danger' if any([e for e in self.errors if e.field == name]) else ""

    def summary(self, name=None):
        errors = [e.message for e in self.errors if e.field == name or name == '@all']
        if len(errors) == 0:
            return ''
        if name is None:
            return Markup('<div class="alert alert-danger">{}</div>'
                    .format('<br />'.join(errors)))
        else:
            return Markup('<div class="form-control-feedback">{}</div>'
                    .format('<br />'.join(errors)))

    def error(self, message, field=None):
        self.errors.append(ValidationError(field, message))

    def optional(self, name, default=None):
        return self.request.form.get(name) or default

    def require(self, name, friendly_name=None):
        value = self.request.form.get(name)
        if not friendly_name:
            friendly_name = name
        if not value:
            self.error('{} is required'.format(friendly_name), field=name)
        return value

    def expect(self, condition, message, field=None):
        if not condition:
            self.error(message, field)
