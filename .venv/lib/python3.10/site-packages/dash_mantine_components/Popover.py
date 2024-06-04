# AUTO GENERATED FILE - DO NOT EDIT

from dash.development.base_component import Component, _explicitize_args


class Popover(Component):
    """A Popover component.
over

Keyword arguments:

- children (a list of or a singular dash component, string or number; optional):
    `Popover.Target` and `Popover.Dropdown` components.

- id (string; optional):
    Unique ID to identify this component in Dash callbacks.

- aria-* (string; optional):
    Wild card aria attributes.

- arrowOffset (number; optional):
    Arrow offset in px, `5` by default.

- arrowPosition (a value equal to: 'center', 'side'; optional):
    Arrow position.

- arrowRadius (number; optional):
    Arrow `border-radius` in px, `0` by default.

- arrowSize (number; optional):
    Arrow size in px, `7` by default.

- boxWrapperProps (dict; optional):
    Target box wrapper props.

    `boxWrapperProps` is a dict with keys:

    - bg (boolean | number | string | dict | list; optional)

    - bga (boolean | number | string | dict | list; optional)

    - bgp (string | number; optional)

    - bgr (boolean | number | string | dict | list; optional)

    - bgsz (string | number; optional)

    - bottom (string | number; optional)

    - c (boolean | number | string | dict | list; optional)

    - className (string; optional):
        Class added to the root element, if applicable.

    - darkHidden (boolean; optional):
        Determines whether component should be hidden in dark color
        scheme with `display: none`.

    - display (boolean | number | string | dict | list; optional)

    - ff (boolean | number | string | dict | list; optional)

    - flex (string | number; optional)

    - fs (boolean | number | string | dict | list; optional)

    - fw (boolean | number | string | dict | list; optional)

    - fz (number; optional)

    - h (string | number; optional)

    - hiddenFrom (boolean | number | string | dict | list; optional):
        Breakpoint above which the component is hidden with `display:
        none`.

    - inset (string | number; optional)

    - left (string | number; optional)

    - lh (number; optional)

    - lightHidden (boolean; optional):
        Determines whether component should be hidden in light color
        scheme with `display: none`.

    - lts (string | number; optional)

    - m (number; optional)

    - mah (string | number; optional)

    - maw (string | number; optional)

    - mb (number; optional)

    - me (number; optional)

    - mih (string | number; optional)

    - miw (string | number; optional)

    - ml (number; optional)

    - mod (string; optional):
        Element modifiers transformed into `data-` attributes, for
        example, `{ 'data-size': 'xl' }`, falsy values are removed.

    - mr (number; optional)

    - ms (number; optional)

    - mt (number; optional)

    - mx (number; optional)

    - my (number; optional)

    - opacity (boolean | number | string | dict | list; optional)

    - p (number; optional)

    - pb (number; optional)

    - pe (number; optional)

    - pl (number; optional)

    - pos (boolean | number | string | dict | list; optional)

    - pr (number; optional)

    - ps (number; optional)

    - pt (number; optional)

    - px (number; optional)

    - py (number; optional)

    - right (string | number; optional)

    - style (boolean | number | string | dict | list; optional):
        Inline style added to root component element, can subscribe to
        theme defined on MantineProvider.

    - ta (boolean | number | string | dict | list; optional)

    - td (string | number; optional)

    - top (string | number; optional)

    - tt (boolean | number | string | dict | list; optional)

    - visibleFrom (boolean | number | string | dict | list; optional):
        Breakpoint below which the component is hidden with `display:
        none`.

    - w (string | number; optional)

- classNames (dict; optional):
    Adds class names to Mantine components.

- clickOutsideEvents (list of strings; optional):
    Events that trigger outside clicks.

- closeOnClickOutside (boolean; optional):
    Determines whether dropdown should be closed on outside clicks,
    `True` by default.

- closeOnEscape (boolean; optional):
    Determines whether dropdown should be closed when `Escape` key is
    pressed, `True` by default.

- data-* (string; optional):
    Wild card data attributes.

- disabled (boolean; optional):
    If set, popover dropdown will not be rendered.

- floatingStrategy (a value equal to: 'fixed', 'absolute'; optional):
    Changes floating ui [position
    strategy](https://floating-ui.com/docs/usefloating#strategy),
    `'absolute'` by default.

- keepMounted (boolean; optional):
    If set dropdown will not be unmounted from the DOM when it is
    hidden, `display: none` styles will be added instead.

- middlewares (dict; optional):
    Floating ui middlewares to configure position handling, `{ flip:
    True, shift: True, inline: False }` by default.

    `middlewares` is a dict with keys:

    - flip (dict; optional)

        `flip` is a dict with keys:

        - altBoundary (boolean; optional):

            Whether to check for overflow using the alternate element's

            boundary  (`clippingAncestors` boundary only).

            @,default,False.

        - boundary (list of a list of or a singular dash component, string or numbers; optional)

        - crossAxis (boolean; optional):

            The axis that runs along the alignment of the floating

            element. Determines  whether overflow along this axis is

            checked to perform a flip. @,default,True.

        - elementContext (a value equal to: 'reference', 'floating'; optional):

            The element in which overflow is being checked relative to a

            boundary. @,default,'floating'.

        - fallbackAxisSideDirection (a value equal to: 'end', 'start', 'none'; optional):

            Whether to allow fallback to the perpendicular axis of the

            preferred  placement, and if so, which side direction along

            the axis to prefer. @,default,'none' (disallow fallback).

        - fallbackPlacements (list of a value equal to: 'top', 'left', 'bottom', 'right', 'top-end', 'top-start', 'left-end', 'left-start', 'bottom-end', 'bottom-start', 'right-end', 'right-start's; optional):

            Placements to try sequentially if the preferred `placement`

            does not fit. @,default,[oppositePlacement] (computed).

        - fallbackStrategy (a value equal to: 'bestFit', 'initialPlacement'; optional):

            What strategy to use when no placements fit.

            @,default,'bestFit'.

        - flipAlignment (boolean; optional):

            Whether to flip to placements with the opposite alignment if

            they fit  better. @,default,True.

        - mainAxis (boolean; optional):

            The axis that runs along the side of the floating element.

            Determines  whether overflow along this axis is checked to

            perform a flip. @,default,True.

        - padding (number; optional):

            Virtual padding for the resolved overflow detection offsets.

            @,default,0.

        - rootBoundary (boolean | number | string | dict | list; optional):

            The root clipping area in which overflow will be checked.

            @,default,'viewport'.

    - inline (boolean | number | string | dict | list; optional)

    - shift (dict; optional)

        `shift` is a dict with keys:

        - altBoundary (boolean; optional):

            Whether to check for overflow using the alternate element's

            boundary  (`clippingAncestors` boundary only).

            @,default,False.

        - boundary (list of a list of or a singular dash component, string or numbers; optional)

        - crossAxis (boolean; optional):

            The axis that runs along the side of the floating element.

            Determines  whether overflow along this axis is checked to

            perform shifting. @,default,False.

        - elementContext (a value equal to: 'reference', 'floating'; optional):

            The element in which overflow is being checked relative to a

            boundary. @,default,'floating'.

        - limiter (optional):

            Accepts a function that limits the shifting done in order to

            prevent  detachment.

        - mainAxis (boolean; optional):

            The axis that runs along the alignment of the floating

            element. Determines  whether overflow along this axis is

            checked to perform shifting. @,default,True.

        - padding (number; optional):

            Virtual padding for the resolved overflow detection offsets.

            @,default,0.

        - rootBoundary (boolean | number | string | dict | list; optional):

            The root clipping area in which overflow will be checked.

            @,default,'viewport'.

    - size (optional)

- offset (number; optional):
    Offset of the dropdown element, `8` by default.

- opened (boolean; optional):
    Controlled dropdown opened state.

- portalProps (dict; optional):
    Props to pass down to the `Portal` when `withinPortal` is True.

- position (a value equal to: 'top', 'left', 'bottom', 'right', 'top-end', 'top-start', 'left-end', 'left-start', 'bottom-end', 'bottom-start', 'right-end', 'right-start'; optional):
    Dropdown position relative to the target element, `'bottom'` by
    default.

- positionDependencies (list of boolean | number | string | dict | lists; optional):
    `useEffect` dependencies to force update dropdown position, `[]`
    by default.

- radius (number; optional):
    Key of `theme.radius` or any valid CSS value to set border-radius,
    `theme.defaultRadius` by default.

- returnFocus (boolean; optional):
    Determines whether focus should be automatically returned to
    control when dropdown closes, `False` by default.

- shadow (boolean | number | string | dict | list; optional):
    Key of `theme.shadows` or any other valid CSS `box-shadow` value.

- styles (boolean | number | string | dict | list; optional):
    Mantine styles API.

- tabIndex (number; optional):
    tab-index.

- transitionProps (dict; optional):
    Props passed down to the `Transition` component that used to
    animate dropdown presence, use to configure duration and animation
    type, `{ duration: 150, transition: 'fade' }` by default.

    `transitionProps` is a dict with keys:

    - children (optional):
        Render function with transition styles argument.

    - duration (number; optional):
        Transition duration in ms, `250` by default.

    - exitDuration (number; optional):
        Exit transition duration in ms, `250` by default.

    - keepMounted (boolean; optional):
        If set element will not be unmounted from the DOM when it is
        hidden, `display: none` styles will be applied instead.

    - onEnter (optional):
        Called when enter transition starts.

    - onEntered (optional):
        Called when enter transition ends.

    - onExit (optional):
        Called when exit transition starts.

    - onExited (optional):
        Called when exit transition ends.

    - timingFunction (string; optional):
        Transition timing function, `theme.transitionTimingFunction`
        by default.

    - transition (boolean | number | string | dict | list; optional):
        Transition name or object.

- trapFocus (boolean; optional):
    Determines whether focus should be trapped within dropdown,
    `False` by default.

- unstyled (boolean; optional):
    Remove all Mantine styling from the component.

- variant (string; optional):
    variant.

- width (string | number; optional):
    Dropdown width, or `'target'` to make dropdown width the same as
    target element, `'max-content'` by default.

- withArrow (boolean; optional):
    Determines whether component should have an arrow, `False` by
    default.

- withRoles (boolean; optional):
    Determines whether dropdown and target elements should have
    accessible roles, `True` by default.

- withinPortal (boolean; optional):
    Determines whether dropdown should be rendered within the
    `Portal`, `True` by default.

- zIndex (string | number; optional):
    Dropdown `z-index`, `300` by default."""
    _children_props = ['middlewares.shift.boundary', 'middlewares.flip.boundary']
    _base_nodes = ['children']
    _namespace = 'dash_mantine_components'
    _type = 'Popover'
    @_explicitize_args
    def __init__(self, children=None, boxWrapperProps=Component.UNDEFINED, opened=Component.UNDEFINED, closeOnClickOutside=Component.UNDEFINED, clickOutsideEvents=Component.UNDEFINED, trapFocus=Component.UNDEFINED, closeOnEscape=Component.UNDEFINED, withRoles=Component.UNDEFINED, position=Component.UNDEFINED, offset=Component.UNDEFINED, positionDependencies=Component.UNDEFINED, keepMounted=Component.UNDEFINED, transitionProps=Component.UNDEFINED, width=Component.UNDEFINED, middlewares=Component.UNDEFINED, withArrow=Component.UNDEFINED, arrowSize=Component.UNDEFINED, arrowOffset=Component.UNDEFINED, arrowRadius=Component.UNDEFINED, arrowPosition=Component.UNDEFINED, withinPortal=Component.UNDEFINED, portalProps=Component.UNDEFINED, zIndex=Component.UNDEFINED, radius=Component.UNDEFINED, shadow=Component.UNDEFINED, disabled=Component.UNDEFINED, returnFocus=Component.UNDEFINED, floatingStrategy=Component.UNDEFINED, classNames=Component.UNDEFINED, styles=Component.UNDEFINED, unstyled=Component.UNDEFINED, variant=Component.UNDEFINED, id=Component.UNDEFINED, tabIndex=Component.UNDEFINED, **kwargs):
        self._prop_names = ['children', 'id', 'aria-*', 'arrowOffset', 'arrowPosition', 'arrowRadius', 'arrowSize', 'boxWrapperProps', 'classNames', 'clickOutsideEvents', 'closeOnClickOutside', 'closeOnEscape', 'data-*', 'disabled', 'floatingStrategy', 'keepMounted', 'middlewares', 'offset', 'opened', 'portalProps', 'position', 'positionDependencies', 'radius', 'returnFocus', 'shadow', 'styles', 'tabIndex', 'transitionProps', 'trapFocus', 'unstyled', 'variant', 'width', 'withArrow', 'withRoles', 'withinPortal', 'zIndex']
        self._valid_wildcard_attributes =            ['data-', 'aria-']
        self.available_properties = ['children', 'id', 'aria-*', 'arrowOffset', 'arrowPosition', 'arrowRadius', 'arrowSize', 'boxWrapperProps', 'classNames', 'clickOutsideEvents', 'closeOnClickOutside', 'closeOnEscape', 'data-*', 'disabled', 'floatingStrategy', 'keepMounted', 'middlewares', 'offset', 'opened', 'portalProps', 'position', 'positionDependencies', 'radius', 'returnFocus', 'shadow', 'styles', 'tabIndex', 'transitionProps', 'trapFocus', 'unstyled', 'variant', 'width', 'withArrow', 'withRoles', 'withinPortal', 'zIndex']
        self.available_wildcard_properties =            ['data-', 'aria-']
        _explicit_args = kwargs.pop('_explicit_args')
        _locals = locals()
        _locals.update(kwargs)  # For wildcard attrs and excess named props
        args = {k: _locals[k] for k in _explicit_args if k != 'children'}

        super(Popover, self).__init__(children=children, **args)
