# AUTO GENERATED FILE - DO NOT EDIT

from dash.development.base_component import Component, _explicitize_args


class NavigationProgress(Component):
    """A NavigationProgress component.
igationProgress

Keyword arguments:

- intent (a value equal to: 'start', 'stop', 'increment', 'decrement', 'set', 'reset', 'complete'; required):
    intent.

- value (number; optional):
    value to set the progress bar to."""
    _children_props = []
    _base_nodes = ['children']
    _namespace = 'dash_mantine_components'
    _type = 'NavigationProgress'
    @_explicitize_args
    def __init__(self, intent=Component.REQUIRED, value=Component.UNDEFINED, **kwargs):
        self._prop_names = ['intent', 'value']
        self._valid_wildcard_attributes =            []
        self.available_properties = ['intent', 'value']
        self.available_wildcard_properties =            []
        _explicit_args = kwargs.pop('_explicit_args')
        _locals = locals()
        _locals.update(kwargs)  # For wildcard attrs and excess named props
        args = {k: _locals[k] for k in _explicit_args}

        for k in ['intent']:
            if k not in args:
                raise TypeError(
                    'Required argument `' + k + '` was not specified.')

        super(NavigationProgress, self).__init__(**args)
