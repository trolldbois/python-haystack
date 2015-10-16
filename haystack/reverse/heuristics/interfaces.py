# -*- coding: utf-8 -*-


class IReverser(object):
    """
    Signature for a reverser.
    """
    def reverse(self):
        """
        Run the reversing algorithm.

        :return:
        """
        raise NotImplementedError(self)


class IContextReverser(object):
    """
    Signature for a reverser.
    """
    def reverse_context(self, _context):
        """
        Run the reversing algorithm.

        :return:
        """
        raise NotImplementedError(self)


class IRecordReverser(object):
    """
    A class that will apply reversing heuristics on a Record scope.
    """
    def reverse_record(self, _record):
        """
        Run the reversing algorithm on this record

        :param _record: the target of the reverse heuristics.
        :return:
        """
        raise NotImplementedError(self)

    def get_reverse_level(self):
        """
        Return the level of reversing that this IReverser brings to the record.
        Basically help in ordering reversers between them.
        """
        raise NotImplementedError(self)


class IFieldReverser(object):
    """
    A class that will apply reversing heuristics on a Field scope.
    """
    def reverse_field(self, _field):
        """
        Run the reversing algorithm on this field

        :param _field: the target of the reverse heuristics.
        :return:
        """
        raise NotImplementedError(self)
